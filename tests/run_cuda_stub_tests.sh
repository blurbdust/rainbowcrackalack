#!/bin/sh
#
# Rainbow Crackalack: tests/run_cuda_stub_tests.sh
#
# Build and run the CUDA backend's host-side tests against the fake driver in
# tests/cuda_stub/.  Needs no GPU and no CUDA toolkit, so this runs on an
# ordinary CI runner -- which is the point: the CUDA backend was otherwise
# entirely untested by CI.
#
# Runs twice, once plain and once under ThreadSanitizer.  The registry these
# tests cover is touched by one thread per GPU, and it used to be mutated with
# no lock; only the TSan pass catches that.
#
# Usage: tests/run_cuda_stub_tests.sh

set -eu

cd "$(dirname "$0")/.."

STUB_DIR=tests/cuda_stub
OUT_DIR=build/cuda-stub
SRCS="cuda_setup.c $STUB_DIR/cuda_stub.c tests/test_cuda_arg_tables.c"

# -I$STUB_DIR ahead of everything so <cuda.h>/<nvrtc.h> resolve to the stubs
# even on a machine that does have the real toolkit installed.
COMMON="-DUSE_CUDA -I$STUB_DIR -I. -std=gnu11 -Wall -g"

mkdir -p "$OUT_DIR"

status=0

echo "=== CUDA stub tests (plain) ==="
# shellcheck disable=SC2086
cc $COMMON -o "$OUT_DIR/test_cuda_arg_tables" $SRCS -lpthread
"$OUT_DIR/test_cuda_arg_tables" || status=1

echo
echo "=== CUDA stub tests (ThreadSanitizer) ==="
if cc $COMMON -fsanitize=thread -o "$OUT_DIR/test_cuda_arg_tables_tsan" $SRCS -lpthread 2>/dev/null; then
  TSAN_OPTIONS="halt_on_error=1 exitcode=1" "$OUT_DIR/test_cuda_arg_tables_tsan" || status=1
else
  echo "ThreadSanitizer unavailable on this toolchain; skipping."
fi

exit $status
