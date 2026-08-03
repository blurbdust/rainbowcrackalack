#!/usr/bin/env python3
#
# Rainbow Crackalack: tests/test_netntlmv1.py
#
# Correctness tests for the Net-NTLMv1 code path.  These run on any OpenCL
# device, including a CPU ICD such as pocl, so they work on CI machines with no
# GPU.
#
# Three suites:
#
#   reference  Anchor the independent Python model (tests/netntlmv1_ref.py) on
#              published DES vectors and on the Net-NTLMv1 capture published in
#              Mandiant's Net-NTLMv1 deprecation writeup.
#
#   generate   Run crackalack_gen and check the resulting tables two ways: a
#              golden SHA-256 of the whole file, and a chain-by-chain
#              recomputation with the Python model.  The golden hash catches any
#              change at all; the recomputation says which chain broke and how.
#              This is the only CPU-side verification Net-NTLMv1 tables get --
#              crackalack_gen's built-in verifier skips non-NTLM hash types.
#
#   lookup     Plant a known chain in an otherwise random table, then check that
#              crackalack_lookup recovers exactly the right 7-byte DES key.
#              Exercises the precompute kernel, the binary search and the false
#              alarm check without needing a real multi-gigabyte table.
#
# Usage: tests/test_netntlmv1.py [reference | generate | lookup]   (default: all)
#

import hashlib
import os
import random
import re
import shutil
import struct
import subprocess
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import netntlmv1_ref as ref

REPO_ROOT = os.environ.get(
    "CRACKALACK_ROOT",
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
GEN_PROG = os.path.join(REPO_ROOT, "crackalack_gen")
LOOKUP_PROG = os.path.join(REPO_ROOT, "crackalack_lookup")

GREEN, RED, CLR = "\033[0;32m", "\033[0;31m", "\033[0m"
_ANSI = re.compile(r"\x1b\[[0-9;]*m")

# Generation tests: (crackalack_gen args, sha256 of the resulting .rt file).
# These are stable across devices and work-group sizes -- chain contents and
# ordering depend only on the parameters, not on the OpenCL device.  Regenerate
# with:  crackalack_gen <args> && sha256sum *.rt
GEN_TESTS = [
    (["netntlmv1", "byte", "7", "7", "0", "100", "1024", "0"],
     "33bdc965e44297388fc66f47d8b818d15832cb3e60dd9474a0f98b80827e7100"),
    # Non-zero table index, to cover the reduction offset.
    (["netntlmv1", "byte", "7", "7", "3", "100", "1024", "0"],
     "a87c39cdf20aca15cb2afe0e434d552385c79c9c029d350ea76dea8210c5fcc8"),
    # Non-zero part index, to cover the start-index base (part * num_chains).
    (["netntlmv1", "byte", "7", "7", "0", "500", "2048", "5"],
     "a06dd786ae3a3e00da9de6854f5336e54b1b0e4cc39564e48eeb837a94ae509e"),
]

# Lookup tests: (table_index, chain_len, num_chains, chain start index,
# position in the chain whose hash we look up).
LOOKUP_TESTS = [
    (0, 100, 1024, 424242, 37),
    (3, 100, 1024, 999, 0),    # first position, non-zero reduction offset
    (0, 250, 2048, 8675309, 248),  # last position in the chain
]


def strip_ansi(s):
    return _ANSI.sub("", s)


def fail(msg):
    print("%sFAILED%s: %s" % (RED, CLR, msg))
    return False


# Kernel sources live in a per-backend directory, and the binaries load them
# from the working directory at runtime.
KERNEL_DIRS = ("CL", "CUDA", "Metal")


def make_workdir():
    """Tests run in a scratch dir, so copy whichever kernel trees exist.

    Which one gets used depends on the backend the binaries were built
    against, so copying all present keeps this suite backend-agnostic.
    """
    tmp = tempfile.mkdtemp(prefix="netntlmv1_tests")
    copied = []
    for name in KERNEL_DIRS:
        src = os.path.join(REPO_ROOT, name)
        if os.path.isdir(src):
            shutil.copytree(src, os.path.join(tmp, name))
            shutil.copy(os.path.join(REPO_ROOT, "shared.h"), os.path.join(tmp, name))
            copied.append(name)
    if not copied:
        raise RuntimeError("no kernel directory (%s) found under %s"
                           % (", ".join(KERNEL_DIRS), REPO_ROOT))
    return tmp


def read_table(path):
    """A .rt file is a flat array of (start_index, end_index) little-endian u64 pairs."""
    with open(path, "rb") as f:
        data = f.read()
    if len(data) % 16 != 0:
        raise ValueError("%s: size %u is not a multiple of 16" % (path, len(data)))
    return [struct.unpack_from("<QQ", data, i * 16) for i in range(len(data) // 16)]


def write_table(path, chains):
    """Write chains sorted by end index, as crackalack_lookup binary-searches them."""
    with open(path, "wb") as f:
        for start, end in sorted(chains, key=lambda c: c[1]):
            f.write(struct.pack("<QQ", start, end))


# --- reference ---------------------------------------------------------------

def do_reference_tests():
    print("Checking the independent Python model... ", end="", flush=True)
    try:
        ref.self_test()
    except AssertionError:
        return fail("netntlmv1_ref self-test failed -- the model itself is wrong")

    # Rebuild the whole 24-byte Net-NTLMv1 response from the published NTLM hash
    # and compare against the published capture.  This pins down the fixed
    # challenge, the 16->21 byte NTLM padding and the 7-byte key split.
    ntlm = bytes.fromhex("9e969e23a39134884488e0247650fffc")
    padded = ntlm + b"\x00" * 5
    response = b"".join(ref.netntlmv1_hash(padded[i:i + 7]) for i in (0, 7, 14))
    expected = "59b8beffd0c2aec5a9d83c6ca210be62cec31640e20cbfca"
    if response.hex() != expected:
        return fail("response mismatch:\n  expected %s\n  actual   %s"
                    % (expected, response.hex()))

    print("%spassed.%s" % (GREEN, CLR))
    return True


# --- generate ----------------------------------------------------------------

def do_generate_tests(workdir):
    all_passed = True
    for args, expected_hash in GEN_TESTS:
        print("Generating table: %s... " % " ".join(args), end="", flush=True)

        for stale in os.listdir(workdir):
            if stale.endswith(".rt"):
                os.unlink(os.path.join(workdir, stale))

        proc = subprocess.run([GEN_PROG] + args, cwd=workdir,
                              stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        if proc.returncode != 0:
            all_passed = fail("crackalack_gen exited %d:\n%s"
                              % (proc.returncode, strip_ansi(proc.stdout.decode("utf-8", "replace"))))
            continue

        tables = [f for f in os.listdir(workdir) if f.endswith(".rt")]
        if len(tables) != 1:
            all_passed = fail("expected exactly one .rt file, got %r" % tables)
            continue
        table_path = os.path.join(workdir, tables[0])

        with open(table_path, "rb") as f:
            actual_hash = hashlib.sha256(f.read()).hexdigest()

        chain_len = int(args[5])
        num_chains = int(args[6])
        reduction_offset = ref.table_index_to_reduction_offset(int(args[4]))
        chains = read_table(table_path)

        if len(chains) != num_chains:
            all_passed = fail("expected %u chains, got %u" % (num_chains, len(chains)))
            os.unlink(table_path)
            continue

        # Recompute a spread-out sample of chains with the Python model.  A
        # prime stride keeps the sample deterministic but not clustered.
        bad = []
        for start, end in chains[::97]:
            calculated, _, _ = ref.walk_chain(start, chain_len, reduction_offset)
            if calculated != end:
                bad.append((start, end, calculated))
        if bad:
            start, end, calculated = bad[0]
            all_passed = fail("%u of %u sampled chains disagree with the reference; "
                              "first: start=%u table_end=%u reference_end=%u"
                              % (len(bad), len(chains[::97]), start, end, calculated))
            os.unlink(table_path)
            continue

        if actual_hash != expected_hash:
            all_passed = fail("table sha256 mismatch (chains verify against the "
                              "reference, so the change is in file layout or "
                              "chain ordering)\n  expected: %s\n  actual:   %s"
                              % (expected_hash, actual_hash))
            os.unlink(table_path)
            continue

        os.unlink(table_path)
        print("%spassed%s (%u chains verified against the reference)."
              % (GREEN, CLR, len(chains[::97])))

    return all_passed


# --- lookup ------------------------------------------------------------------

def do_lookup_tests(workdir):
    all_passed = True
    for table_index, chain_len, num_chains, start_index, position in LOOKUP_TESTS:
        print("Lookup: table_index=%u chain_len=%u position=%u... "
              % (table_index, chain_len, position), end="", flush=True)

        reduction_offset = ref.table_index_to_reduction_offset(table_index)
        end_index, plaintext, hash_value = ref.walk_chain(
            start_index, chain_len, reduction_offset, stop_at=position)
        if plaintext is None:
            all_passed = fail("position %u is outside the chain" % position)
            continue

        rt_dir = tempfile.mkdtemp(prefix="tables", dir=workdir)

        # A table of random chains, with our known-good chain planted in it.
        rng = random.Random(0xC0FFEE + start_index)
        chains = [(start_index, end_index)]
        while len(chains) < num_chains:
            chains.append((rng.getrandbits(56), rng.getrandbits(56)))
        write_table(os.path.join(rt_dir, "netntlmv1_byte#7-7_%u_%ux%u_0.rt"
                                 % (table_index, chain_len, num_chains)), chains)

        hashes_file = os.path.join(rt_dir, "hashes.txt")
        with open(hashes_file, "w") as f:
            f.write(hash_value.hex() + "\n")

        pot_file = os.path.join(rt_dir, "out.pot")
        proc = subprocess.run([LOOKUP_PROG, rt_dir, hashes_file, pot_file],
                              cwd=workdir, stdout=subprocess.PIPE,
                              stderr=subprocess.STDOUT, timeout=1800)
        output = strip_ansi(proc.stdout.decode("utf-8", "replace"))
        if proc.returncode != 0:
            all_passed = fail("crackalack_lookup exited %d:\n%s" % (proc.returncode, output))
            continue

        # The console reports "<hash>:<challenge>:<key hex>".
        expected_line = "%s:1122334455667788:%s" % (hash_value.hex(), plaintext.hex())
        if expected_line not in output:
            all_passed = fail("expected %r in lookup output. Output:\n%s"
                              % (expected_line, output))
            continue

        # The pot file holds "<hash hex>:<raw 7 key bytes>\n" -- the key is
        # written as raw bytes, not hex, so read the file as binary.
        if not os.path.exists(pot_file):
            all_passed = fail("pot file %s was not created" % pot_file)
            continue
        with open(pot_file, "rb") as f:
            pot = f.read()
        if pot != hash_value.hex().encode() + b":" + plaintext + b"\n":
            all_passed = fail("unexpected pot file contents: %r" % pot)
            continue

        shutil.rmtree(rt_dir, ignore_errors=True)
        print("%spassed%s (recovered %s)." % (GREEN, CLR, plaintext.hex()))

    return all_passed


def main():
    suite = sys.argv[1] if len(sys.argv) > 1 else "all"
    if suite not in ("all", "reference", "generate", "lookup"):
        print("Usage: %s [reference | generate | lookup]" % sys.argv[0])
        return 2

    for prog in (GEN_PROG, LOOKUP_PROG):
        if suite != "reference" and not os.path.isfile(prog):
            print("Error: %s not found.  Build it first (see .github/workflows/ci.yml), "
                  "or set CRACKALACK_ROOT." % prog)
            return 2

    workdir = make_workdir()
    passed = True
    try:
        if suite in ("all", "reference"):
            passed &= do_reference_tests()
        if suite in ("all", "generate"):
            passed &= do_generate_tests(workdir)
        if suite in ("all", "lookup"):
            passed &= do_lookup_tests(workdir)
    finally:
        shutil.rmtree(workdir, ignore_errors=True)

    print("\n\t%s%s%s\n" % (GREEN if passed else RED,
                            "ALL NET-NTLMV1 TESTS PASS!" if passed
                            else "SOME NET-NTLMV1 TESTS FAILED!", CLR))
    return 0 if passed else 1


if __name__ == "__main__":
    sys.exit(main())
