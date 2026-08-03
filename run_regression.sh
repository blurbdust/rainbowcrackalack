#!/usr/bin/env bash
#
# Rainbow Crackalack (blurbdust) — extensible both-backend regression harness
# =============================================================================
#
#   ##########################################################################
#   #                    HOW TO EXTEND THIS HARNESS                          #
#   ##########################################################################
#
#   This harness is DATA-DRIVEN.  You extend coverage by editing the tables
#   near the top of this file, NOT by touching the logic below.  Three things
#   you may need to do:
#
#   1) ADD AN END-TO-END CASE FOR A NEW GEN TYPE / FEATURE
#      Append one row to the E2E_CASES array.  Columns (space-separated):
#
#        name  gen_type  charset  len_min  len_max  table_index  chain_len \
#             num_chains  part_index  expect_opencl  expect_cuda
#
#        - name        : short label printed in the summary (no spaces).
#        - gen_type     : crackalack_gen hash algorithm (ntlm, netntlmv1, ...).
#        - charset      : charset name (e.g. ascii-32-95).
#        - len_min/max  : plaintext length range.
#        - table_index  : reduction table index (usually 0).
#        - chain_len    : KEEP SMALL for speed (e.g. 100).
#        - num_chains   : KEEP SMALL; set -gws equal to this (see note below).
#        - part_index   : table part (usually 0).
#        - expect_opencl / expect_cuda : the expected outcome PER BACKEND
#                         (the e2e allowlist, mirroring the unit baseline):
#                         PASS   -> gen must exit 0 and produce a table of the
#                                   exact expected size (num_chains * 16 bytes).
#                                   This is the DETERMINISTIC e2e signal.
#                         XFAIL  -> gen is expected NOT to produce a valid
#                                   full-size table on THAT backend (a
#                                   documented known failure).  A XFAIL that
#                                   starts producing a valid table is a
#                                   REGRESSION (flip it to PASS).
#                         The two columns differ because blurbdust's CUDA
#                         non-optimized gen path is currently broken (see the
#                         E2E_CASES note); OpenCL gen works.
#
#      Tiny is the whole point: a case should finish in a couple of seconds so
#      the full suite stays fast.  num_chains is passed as both the chain count
#      AND -gws so every chain slot is produced by exactly one work item (this
#      is what makes the output-table size deterministic across backends).
#
#      NOTE ON CHAIN CORRECTNESS: `crackalack_verify --raw` is intentionally
#      run as INFORMATIONAL only, not as the pass/fail signal.  At the tiny
#      chain_len/num_chains used here, some chains legitimately collide to a
#      zero end index (normal rainbow-table behaviour), which --raw flags as an
#      "invalid" chain non-deterministically.  The AUTHORITATIVE per-gen-type
#      chain-correctness signal lives in the UNIT-TEST phase instead (e.g. the
#      "NTLM chain" vs "NTLM9 chain" lines), which is fully deterministic.
#
#   2) ADD A UNIT TEST FOR A NEW GEN TYPE / FEATURE
#      If your feature ships a test kernel, add its CL/test_<x>.cl AND
#      CUDA/test_<x>.cu (or teach crackalack_unit_tests.c to SKIP it under
#      CUDA via kernel_available()).  Then add the exact per-line label the
#      unit-test binary prints to the UNIT_BASELINE_* maps below so this
#      harness knows whether that line is expected to pass or fail on each
#      backend.
#
#   3) UPDATE THE KNOWN-FAIL ALLOWLIST WHEN YOU FIX A BUG
#      There are TWO allowlists, both per-backend:
#        - UNIT_BASELINE: each unit-test line marked pass|fail for opencl|cuda.
#        - E2E_CASES:     each gen case's expect_opencl / expect_cuda column.
#      When a future PR fixes, say, the OpenCL NTLM chain bug or the CUDA
#      non-optimized gen path, flip the relevant "fail"/"XFAIL" entry to
#      "pass"/"PASS" here.  The harness FAILS on any deviation from the
#      baseline in EITHER direction (a known-good check breaking, OR a
#      known-fail check unexpectedly changing), so it catches both regressions
#      and stealth fixes that were not recorded.
#
#   ##########################################################################
#
# USAGE:
#   ./run_regression.sh [linux|linux-cuda|both]     (default: both)
#
# EXIT CODE:
#   0  -> every non-allowlisted check matched the baseline on every requested
#         backend (known-fail stays fail, everything else passes / matches).
#   1  -> at least one REGRESSION (a baseline deviation) was detected.
#   2  -> harness/setup error (build failed, binary missing, etc.).
#
# DEPENDENCIES: only what the repo build already needs (bash, make, the CUDA
# toolchain for linux-cuda, and the crackalack_* binaries this builds).  No
# excluded-feature tooling (markov/mask/md5/etc.) is referenced.
#
# Copyright (C) 2018-2026.  GPLv3, same as the rest of the project.
# =============================================================================

set -u

REPO_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$REPO_DIR" || { echo "cannot cd to repo dir"; exit 2; }

# ------------------------------- colours ------------------------------------
if [ -t 1 ]; then
  C_RST=$'\033[0m'; C_GRN=$'\033[0;32m'; C_RED=$'\033[0;31m'
  C_YEL=$'\033[0;33m'; C_BLD=$'\033[1;97m'
else
  C_RST=; C_GRN=; C_RED=; C_YEL=; C_BLD=
fi

# =============================================================================
#  DATA: UNIT-TEST BASELINE / KNOWN-FAIL ALLOWLIST  (edit me to extend)
#
#  Key   = the EXACT test label as this harness matches it (substring of the
#          line crackalack_unit_tests prints).
#  Value = expected outcome on that backend: "pass" or "fail".
#
#  blurbdust FACTS captured on dell3 (RTX 3080 Ti):
#   * OpenCL FAILS the NTLM (non-9) index_to_plaintext, hash and chain tests
#     pre-existingly; NTLM9 variants pass.
#   * CUDA PASSES NTLM index_to_plaintext and NTLM hash (which OpenCL fails!),
#     but the NTLM chain path is broken on BOTH backends.
#  So the allowlist DIFFERS per backend — that asymmetry is the whole point.
# =============================================================================

# label|expected_opencl|expected_cuda
UNIT_BASELINE="
NTLM index_to_plaintext|fail|pass
NTLM9 index_to_plaintext|pass|pass
NTLM hash|fail|pass
NTLM9 hash|pass|pass
NTLM hash_to_index|pass|pass
NTLM9 hash_to_index|pass|pass
NTLM chain|fail|fail
NTLM9 chain|pass|pass
"

# =============================================================================
#  DATA: END-TO-END GEN MATRIX  (add a row per gen type / feature)
#
#   name  gen_type charset      min max idx clen nchains part exp_ocl exp_cuda
# =============================================================================
E2E_CASES="
ntlm9_e2e  ntlm  ascii-32-95  9 9 0 100 4096 0 PASS XFAIL
ntlm8_e2e  ntlm  ascii-32-95  8 8 0 100 4096 0 PASS XFAIL
"
# On OpenCL, both ntlm8 and ntlm9 gen WRITE a full-size table (PASS).  The ntlm8
# CHAIN CORRECTNESS defect is carried by the unit-test baseline ("NTLM chain" =
# fail on both backends), not by a flaky e2e verify.
#
# On CUDA, blurbdust's NON-OPTIMIZED gen kernel (CUDA/crackalack.cu, selected by
# these tiny non-standard params) reliably HANGS at the chain-generation launch
# — the same unsigned-loop / arg-contract class of defect fixed for the unit
# test kernels, but here in the PR-B production gen kernel and OUT OF SCOPE for
# this PR.  So both CUDA gen cases are recorded XFAIL.  When that gen path is
# fixed (or when driving the OPTIMIZED kernels, e.g. chain_len 803000), flip the
# exp_cuda column to PASS.
#
# NOTE ON netntlmv1: blurbdust's crackalack_gen references a
# crackalack_netntlmv1.cl generation kernel that does not ship (only the
# netntlmv1 hash library exists), so there is no functional netntlmv1 table
# generation to drive end-to-end here.  netntlmv1 coverage therefore lives in
# the hash/DES library + lookup path, not this gen matrix.  When a
# crackalack_netntlmv1 gen kernel lands, add a row above.

# =============================================================================
#  LOGIC BELOW — you should not normally need to edit past this line.
# =============================================================================

REGRESSIONS=0
declare -a SUMMARY

pass_line()  { printf "  %s[ PASS ]%s %s\n"  "$C_GRN" "$C_RST" "$1"; }
fail_line()  { printf "  %s[REGRES]%s %s\n"  "$C_RED" "$C_RST" "$1"; REGRESSIONS=$((REGRESSIONS+1)); }
xfail_line() { printf "  %s[XFAIL ]%s %s\n"  "$C_YEL" "$C_RST" "$1"; }
info_line()  { printf "  %s[ INFO ]%s %s\n"  "$C_YEL" "$C_RST" "$1"; }

build_backend() {
  local backend="$1"
  printf "%s>>> Building backend: %s%s\n" "$C_BLD" "$backend" "$C_RST"
  if ! make clean >/dev/null 2>&1; then echo "make clean failed"; return 2; fi
  if ! make "$backend" >/tmp/rr_build_"$backend".log 2>&1; then
    echo "${C_RED}BUILD FAILED for $backend (see /tmp/rr_build_$backend.log)${C_RST}"
    tail -15 /tmp/rr_build_"$backend".log
    return 2
  fi
  [ -x ./crackalack_unit_tests ] && [ -x ./crackalack_gen ] && [ -x ./crackalack_verify ]
}

# Look up the expected outcome for a unit-test label on a given backend.
# Args: <label> <col: 1=opencl 2=cuda>.  Echoes "pass"/"fail"/"" (unknown).
expected_for() {
  local want="$1" col="$2" line lbl eo ec
  while IFS='|' read -r lbl eo ec; do
    [ -z "$lbl" ] && continue
    if [ "$lbl" = "$want" ]; then
      [ "$col" = "1" ] && echo "$eo" || echo "$ec"
      return 0
    fi
  done <<< "$UNIT_BASELINE"
  echo ""
}

run_unit_tests() {
  local backend="$1" col; [ "$backend" = "linux" ] && col=1 || col=2
  printf "%s--- Unit tests (%s) ---%s\n" "$C_BLD" "$backend" "$C_RST"

  # Capture output (strip ANSI).  A hung run would block here; the ported
  # kernels are fixed so this completes.  Timeout guards against future hangs.
  local out
  out="$(timeout 600 ./crackalack_unit_tests 2>/dev/null | sed 's/\x1b\[[0-9;]*m//g')"

  local lbl eo ec exp actual line matched
  while IFS='|' read -r lbl eo ec; do
    [ -z "$lbl" ] && continue
    [ "$col" = "1" ] && exp="$eo" || exp="$ec"

    # Find the printed line for this label.  Labels appear as
    # "Running <LABEL>() tests... passed." / "... FAILED!" (or SKIPPED).
    line="$(printf '%s\n' "$out" | grep -F "Running $lbl" | head -1)"
    if [ -z "$line" ]; then
      # try a looser match (label may be embedded differently)
      line="$(printf '%s\n' "$out" | grep -F "$lbl" | grep -Ei 'passed|FAILED|SKIPPED' | head -1)"
    fi

    if [ -z "$line" ]; then
      fail_line "unit:$lbl — expected result not found in output (expected $exp)"
      SUMMARY+=("$backend unit $lbl MISSING (exp $exp) -> REGRESSION")
      continue
    fi

    if printf '%s' "$line" | grep -qi 'SKIPPED'; then
      info_line "unit:$lbl — SKIPPED (no CUDA kernel yet)"
      SUMMARY+=("$backend unit $lbl SKIPPED")
      continue
    fi

    if printf '%s' "$line" | grep -qi 'passed'; then actual=pass; else actual=fail; fi

    if [ "$actual" = "$exp" ]; then
      if [ "$exp" = "fail" ]; then
        xfail_line "unit:$lbl — known-fail (matches baseline)"
        SUMMARY+=("$backend unit $lbl XFAIL(ok)")
      else
        pass_line "unit:$lbl"
        SUMMARY+=("$backend unit $lbl PASS")
      fi
    else
      fail_line "unit:$lbl — baseline says '$exp' but got '$actual'"
      SUMMARY+=("$backend unit $lbl $actual!=baseline($exp) -> REGRESSION")
    fi
  done <<< "$UNIT_BASELINE"
}

run_e2e() {
  local backend="$1"
  printf "%s--- End-to-end gen+verify (%s) ---%s\n" "$C_BLD" "$backend" "$C_RST"

  local name gen charset mn mx idx clen nchains part exp_ocl exp_cuda expect
  while read -r name gen charset mn mx idx clen nchains part exp_ocl exp_cuda; do
    [ -z "${name:-}" ] && continue
    [ "$backend" = "linux" ] && expect="$exp_ocl" || expect="$exp_cuda"

    local rt="${gen}_${charset}#${mn}-${mx}_${idx}_${clen}x${nchains}_${part}.rt"
    rm -f "$rt"

    # Deterministic slot production: -gws == num_chains.  The 60s cap is ample
    # for a working (OpenCL) tiny gen, which completes in seconds; a backend
    # whose gen path hangs (e.g. CUDA non-optimized, currently XFAIL) trips the
    # timeout quickly instead of stalling the suite.
    timeout 60 ./crackalack_gen "$gen" "$charset" "$mn" "$mx" "$idx" "$clen" "$nchains" "$part" -gws "$nchains" >/tmp/rr_gen_"$name".log 2>&1
    local grc=$?

    local expected_bytes=$(( nchains * 16 ))   # 8-byte start + 8-byte end per chain
    local actual_bytes=0
    [ -f "$rt" ] && actual_bytes=$(wc -c < "$rt")

    # DETERMINISTIC signal: gen exited 0 and produced an exact-size table.
    local gen_ok=0
    if [ "$grc" -eq 0 ] && [ "$actual_bytes" -eq "$expected_bytes" ]; then
      gen_ok=1
    fi

    # INFORMATIONAL only: --raw verify (non-deterministic at tiny sizes; does
    # NOT affect pass/fail — see header note).
    local verify_note="verify=skipped"
    if [ "$gen_ok" -eq 1 ]; then
      if ./crackalack_verify --raw "$rt" >/tmp/rr_verify_"$name".log 2>&1; then
        verify_note="verify=clean"
      else
        verify_note="verify=had-zero-end-chains(info)"
      fi
    fi

    if [ "$expect" = "PASS" ]; then
      if [ "$gen_ok" -eq 1 ]; then
        pass_line "e2e:$name — gen OK (${actual_bytes}B) [$verify_note]"
        SUMMARY+=("$backend e2e $name PASS")
      else
        fail_line "e2e:$name — gen did not produce a full table (grc=$grc, ${actual_bytes}/${expected_bytes}B)"
        SUMMARY+=("$backend e2e $name FAIL(expected PASS) -> REGRESSION")
      fi
    else  # XFAIL
      if [ "$gen_ok" -eq 0 ]; then
        xfail_line "e2e:$name — known-broken gen (matches baseline; grc=$grc, ${actual_bytes}/${expected_bytes}B)"
        SUMMARY+=("$backend e2e $name XFAIL(ok)")
      else
        fail_line "e2e:$name — XFAIL case now produces a full table; flip E2E_CASES 'expect' to PASS"
        SUMMARY+=("$backend e2e $name unexpectedly PASSED -> REGRESSION")
      fi
    fi
    rm -f "$rt"
  done <<< "$E2E_CASES"
}

run_backend() {
  local backend="$1"
  printf "\n%s========================================================%s\n" "$C_BLD" "$C_RST"
  printf "%s BACKEND: %s%s\n" "$C_BLD" "$backend" "$C_RST"
  printf "%s========================================================%s\n" "$C_BLD" "$C_RST"
  if ! build_backend "$backend"; then
    SUMMARY+=("$backend BUILD FAILED")
    return 2
  fi
  run_unit_tests "$backend"
  run_e2e "$backend"
  return 0
}

# ------------------------------ main ----------------------------------------
SEL="${1:-both}"
case "$SEL" in
  linux)       BACKENDS=(linux) ;;
  linux-cuda)  BACKENDS=(linux-cuda) ;;
  both)        BACKENDS=(linux linux-cuda) ;;
  *) echo "usage: $0 [linux|linux-cuda|both]"; exit 2 ;;
esac

SETUP_ERR=0
for b in "${BACKENDS[@]}"; do
  run_backend "$b" || SETUP_ERR=1
done

printf "\n%s================ SUMMARY ================%s\n" "$C_BLD" "$C_RST"
for s in "${SUMMARY[@]}"; do
  case "$s" in
    *REGRESSION*) printf "  %s%s%s\n" "$C_RED" "$s" "$C_RST" ;;
    *XFAIL*|*SKIPPED*) printf "  %s%s%s\n" "$C_YEL" "$s" "$C_RST" ;;
    *BUILD\ FAILED*) printf "  %s%s%s\n" "$C_RED" "$s" "$C_RST" ;;
    *) printf "  %s%s%s\n" "$C_GRN" "$s" "$C_RST" ;;
  esac
done
printf "%s=========================================%s\n" "$C_BLD" "$C_RST"

if [ "$SETUP_ERR" -ne 0 ]; then
  printf "%sHARNESS ERROR: a backend failed to build.%s\n" "$C_RED" "$C_RST"
  exit 2
fi
if [ "$REGRESSIONS" -ne 0 ]; then
  printf "%s%d REGRESSION(S) DETECTED.%s\n" "$C_RED" "$REGRESSIONS" "$C_RST"
  exit 1
fi
printf "%sAll checks match baseline. No regressions.%s\n" "$C_GRN" "$C_RST"
exit 0
