/*
 * Rainbow Crackalack: tests/test_cuda_arg_tables.c
 *
 * Regression tests for cuda_setup.c's per-kernel argument-table registry.
 *
 * Why this exists: crackalack_lookup spawns a fresh false-alarm thread per
 * rainbow table, and each one loads its own module.  cuda_setup.c used to keep
 * arg tables in a fixed 64-entry array that was only ever appended to, because
 * gpu_release_kernel was a no-op.  A two-GPU run therefore aborted partway
 * through table 31 of a 4096-table set -- one thread hit exit(-1) inside the
 * registry while the other was still inside cuModuleGetFunction, and CUDA
 * teardown raced a live thread into a segfault.
 *
 * CI has no GPU and no CUDA toolkit, so this links cuda_setup.c against the
 * fake driver in tests/cuda_stub/ and exercises the bookkeeping directly.
 *
 * Build/run:  tests/run_cuda_stub_tests.sh
 */

#define _GNU_SOURCE  /* mkstemps */

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <pthread.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "gpu_backend.h"
#include "cuda_stub.h"

#define GREEN "\033[0;32m"
#define RED   "\033[0;31m"
#define CLR   "\033[0m"

/* Enough load/release cycles to blow well past the old fixed 64-entry array. */
#define RELOAD_CYCLES 512

#define CHURN_THREADS 4
#define CHURN_CYCLES  128

static const char *g_kernel_path = NULL;
static gpu_device  g_device      = 0;
static gpu_context g_context     = NULL;

static int g_failures = 0;

static void fail(const char *fmt, ...) {
  va_list ap;
  fprintf(stderr, RED "FAIL" CLR ": ");
  va_start(ap, fmt);
  vfprintf(stderr, fmt, ap);
  va_end(ap);
  fprintf(stderr, "\n");
  g_failures++;
}

static void pass(const char *name) {
  printf(GREEN "PASS" CLR ": %s\n", name);
  fflush(stdout);
}

/* load_kernel is chatty (one line per compile or cache hit).  The bulk loops
 * below run it hundreds of times, so mute stderr around them -- but only after
 * at least one un-muted call has proved the path works. */
static int  g_saved_stderr = -1;

static void mute_stderr(void) {
  fflush(stderr);
  g_saved_stderr = dup(STDERR_FILENO);
  int devnull = open("/dev/null", O_WRONLY);
  if (devnull >= 0) { dup2(devnull, STDERR_FILENO); close(devnull); }
}

static void unmute_stderr(void) {
  fflush(stderr);
  if (g_saved_stderr >= 0) {
    dup2(g_saved_stderr, STDERR_FILENO);
    close(g_saved_stderr);
    g_saved_stderr = -1;
  }
}

/* Write a throwaway kernel source for load_kernel to read.  Its contents never
 * matter: NVRTC is stubbed.  The path deliberately does not end in ".cl", so
 * cuda_setup.c's .cl -> CUDA/<base>.cu rewrite leaves it alone. */
static char *write_temp_kernel(void) {
  static char path[] = "/tmp/rcrack_stub_kernel_XXXXXX.cu";
  int fd = mkstemps(path, 3);
  if (fd < 0) {
    fprintf(stderr, "mkstemps failed: %s\n", strerror(errno));
    exit(1);
  }
  const char *src = "__global__ void stub_kernel(void) {}\n";
  if (write(fd, src, strlen(src)) != (ssize_t)strlen(src)) {
    fprintf(stderr, "write to temp kernel failed\n");
    exit(1);
  }
  close(fd);
  return path;
}

static void load_one(gpu_program *program, gpu_kernel *kernel) {
  load_kernel(g_context, 1, &g_device, g_kernel_path, "stub_kernel",
              program, kernel, /*hash_type=*/0);
}

/* ---------------------------------------------------------------------------
 * Test 1: the registry stays bounded across repeated load/release cycles.
 *
 * Against the pre-fix code this does not merely fail an assertion -- the
 * process dies with "cuda_setup: too many tracked kernels (max 64)" on cycle 64.
 * ------------------------------------------------------------------------- */
static void test_registry_bounded_across_reloads(void) {
  gpu_program program = NULL;
  gpu_kernel  kernel  = NULL;
  unsigned int high_water = 0;

  /* One un-muted cycle first, so a broken kernel path reports itself. */
  load_one(&program, &kernel);
  gpu_release_kernel(kernel);
  gpu_release_program(program);

  mute_stderr();
  for (int i = 0; i < RELOAD_CYCLES; i++) {
    load_one(&program, &kernel);

    gpu_buffer buf = gpu_create_buffer(g_context, GPU_RO, 64);
    gpu_set_kernel_arg(kernel, 0, sizeof(gpu_buffer), &buf);

    unsigned int live = cuda_num_tracked_kernels();
    if (live > high_water) high_water = live;

    gpu_release_buffer(buf);
    gpu_release_kernel(kernel);
    gpu_release_program(program);

    if (cuda_num_tracked_kernels() != 0) {
      unmute_stderr();
      fail("registry not empty after release on cycle %d: %u live table(s)",
           i, cuda_num_tracked_kernels());
      return;
    }
  }
  unmute_stderr();

  if (high_water > 1) {
    fail("registry grew to %u live tables with only one kernel loaded at a time",
         high_water);
    return;
  }
  pass("registry stays bounded across 512 kernel load/release cycles");
}

/* ---------------------------------------------------------------------------
 * Test 2: a released kernel's argument bindings do not leak into a later kernel
 * that lands on the same CUfunction address.
 *
 * cuModuleUnload frees its module's function addresses and a later
 * cuModuleGetFunction can hand the same address back.  With a stale arg table
 * keyed on that address, the new kernel silently inherits the dead one's
 * bindings -- wrong results rather than a crash.
 * ------------------------------------------------------------------------- */
static void test_release_evicts_stale_bindings(void) {
  const gpu_buffer sentinel = (gpu_buffer)0xDEADBEEFCAFEULL;
  const unsigned int probe_index = 5;

  gpu_program program = NULL;
  gpu_kernel  kernel  = NULL;

  cuda_stub_set_recycle_functions(1);
  mute_stderr();

  /* First kernel: bind the probe slot to a value we can recognise. */
  load_one(&program, &kernel);
  gpu_kernel first = kernel;
  gpu_set_kernel_arg(kernel, probe_index, sizeof(gpu_buffer), &sentinel);
  gpu_release_kernel(kernel);
  gpu_release_program(program);

  /* Second kernel: same address, and we bind only slot 0. */
  load_one(&program, &kernel);
  unmute_stderr();

  if (kernel != first) {
    fail("stub did not recycle the CUfunction address; test cannot run");
    gpu_release_kernel(kernel);
    gpu_release_program(program);
    cuda_stub_set_recycle_functions(0);
    return;
  }

  gpu_buffer buf = gpu_create_buffer(g_context, GPU_RO, 64);
  gpu_set_kernel_arg(kernel, 0, sizeof(gpu_buffer), &buf);

  gpu_queue queue = gpu_create_queue(g_context, g_device);
  size_t gws = 256;
  cuda_stub_reset_launch_args();
  if (gpu_enqueue_kernel(queue, kernel, 1, &gws) != 0) {
    fail("gpu_enqueue_kernel failed (an unset arg slot was left NULL?)");
  } else {
    CUdeviceptr args[CUDA_STUB_MAX_CAPTURED_ARGS] = {0};
    unsigned int n = cuda_stub_last_launch_args(args, CUDA_STUB_MAX_CAPTURED_ARGS);
    if (n <= probe_index) {
      fail("launch captured only %u args; expected more than %u", n, probe_index);
    } else if (args[probe_index] == (CUdeviceptr)sentinel) {
      fail("recycled kernel inherited the released kernel's binding at slot %u "
           "(0x%" PRIx64 ")", probe_index, (uint64_t)args[probe_index]);
    } else {
      pass("released kernel's bindings do not leak into a recycled CUfunction");
    }
  }

  gpu_release_queue(queue);
  gpu_release_buffer(buf);
  gpu_release_kernel(kernel);
  gpu_release_program(program);
  cuda_stub_set_recycle_functions(0);
}

/* ---------------------------------------------------------------------------
 * Test 3: concurrent load/release from several threads, as the real lookup does
 * with one thread per GPU.  The registry was mutated with no lock at all.
 *
 * A plain run catches gross corruption; build with -fsanitize=thread to catch
 * the race itself (tests/run_cuda_stub_tests.sh does both).
 * ------------------------------------------------------------------------- */
static void *churn_thread(void *arg) {
  (void)arg;
  for (int i = 0; i < CHURN_CYCLES; i++) {
    gpu_program program = NULL;
    gpu_kernel  kernel  = NULL;
    load_one(&program, &kernel);

    gpu_buffer buf = gpu_create_buffer(g_context, GPU_RO, 64);
    gpu_set_kernel_arg(kernel, 0, sizeof(gpu_buffer), &buf);
    gpu_set_kernel_arg(kernel, 1, sizeof(gpu_buffer), &buf);

    gpu_release_buffer(buf);
    gpu_release_kernel(kernel);
    gpu_release_program(program);
  }
  return NULL;
}

static void test_concurrent_churn(void) {
  pthread_t threads[CHURN_THREADS];

  mute_stderr();
  for (int i = 0; i < CHURN_THREADS; i++) {
    if (pthread_create(&threads[i], NULL, churn_thread, NULL) != 0) {
      unmute_stderr();
      fail("pthread_create failed");
      return;
    }
  }
  for (int i = 0; i < CHURN_THREADS; i++)
    pthread_join(threads[i], NULL);
  unmute_stderr();

  unsigned int live = cuda_num_tracked_kernels();
  if (live != 0) {
    fail("%u arg table(s) still live after %d threads x %d cycles",
         live, CHURN_THREADS, CHURN_CYCLES);
    return;
  }
  pass("concurrent load/release leaves no stray arg tables");
}


/* ---------------------------------------------------------------------------
 * Test 4: a cubin survives the on-disk cache byte for byte.
 *
 * The cache was written for PTX, which is text: it stored size-1 bytes to drop
 * the trailing NUL and re-added one on read.  A cubin is binary -- it has no
 * terminator, may contain NULs, and its last byte is significant -- so that
 * same arithmetic silently truncates it, and the corrupted image only surfaces
 * later as a module that will not load.  The other tests here run with the
 * cache switched off, so nothing else covers this.
 * ------------------------------------------------------------------------- */
static const unsigned char EXPECTED_CUBIN[] = {
  0x7f, 'E', 'L', 'F', 0x02, 0x01, 0x01, 0x33,
  0x00, 0x00, 0x00, 0x00, 's', 't', 'u', 'b',
  0x00, 'c', 'u', 'b', 'i', 'n', 0x00, 0xa5
};

static void test_kernel_cache_roundtrip(void) {
  char dir[] = "/tmp/rcrack_stub_cache_XXXXXX";
  if (mkdtemp(dir) == NULL) { fail("mkdtemp failed: %s", strerror(errno)); return; }
  setenv("RCRACK_KERNEL_CACHE", dir, 1);

  gpu_program program = NULL;
  gpu_kernel  kernel  = NULL;

  /* First load compiles and populates the cache. */
  load_one(&program, &kernel);
  gpu_release_kernel(kernel);
  gpu_release_program(program);

  /* Exactly one entry, and it must match the stub cubin byte for byte. */
  DIR *d = opendir(dir);
  if (d == NULL) { fail("opendir(%s) failed", dir); setenv("RCRACK_KERNEL_CACHE", "off", 1); return; }
  char entry[512];
  int found = 0;
  struct dirent *de;
  while ((de = readdir(d)) != NULL) {
    if (de->d_name[0] == '.') continue;
    snprintf(entry, sizeof(entry), "%s/%s", dir, de->d_name);
    found++;
  }
  closedir(d);

  if (found != 1) {
    fail("expected 1 cache entry, found %d (the cubin was never written)", found);
    setenv("RCRACK_KERNEL_CACHE", "off", 1);
    return;
  }

  unsigned char got[64];
  size_t n = 0;
  FILE *f = fopen(entry, "rb");
  if (f) { n = fread(got, 1, sizeof(got), f); fclose(f); }

  if (n != sizeof(EXPECTED_CUBIN)) {
    fail("cached cubin is %zu bytes, expected %zu (truncated by NUL-trimming?)",
         n, sizeof(EXPECTED_CUBIN));
  } else if (memcmp(got, EXPECTED_CUBIN, n) != 0) {
    fail("cached cubin differs from the compiled image");
  } else {
    /* And it must load back, exercising the cache-hit branch. */
    load_one(&program, &kernel);
    if (kernel == NULL) {
      fail("kernel did not load from the cached cubin");
    } else {
      gpu_release_kernel(kernel);
      gpu_release_program(program);
      pass("cubin round-trips through the on-disk cache unchanged");
    }
  }

  unlink(entry);
  rmdir(dir);
  setenv("RCRACK_KERNEL_CACHE", "off", 1);
}

int main(void) {
  /* Keep the on-disk PTX cache out of it: the stub's fake PTX must never be
   * written where a real run could pick it up. */
  setenv("RCRACK_KERNEL_CACHE", "off", 1);

  g_kernel_path = write_temp_kernel();

  gpu_uint num_platforms = 0, num_devices = 0;
  gpu_platform platforms[4];
  gpu_device devices[4];
  get_platforms_and_devices(0, 4, platforms, &num_platforms,
                            4, devices, &num_devices, 0);
  if (num_devices < 1) {
    fprintf(stderr, "stub driver reported no devices\n");
    return 1;
  }
  g_device  = devices[0];
  g_context = gpu_create_context(g_device);
  if (g_context == NULL) {
    fprintf(stderr, "gpu_create_context failed\n");
    return 1;
  }

  test_registry_bounded_across_reloads();
  test_release_evicts_stale_bindings();
  test_concurrent_churn();
  test_kernel_cache_roundtrip();

  int leaked_modules = cuda_stub_live_modules();
  if (leaked_modules != 0)
    fail("%d CUDA module(s) never unloaded", leaked_modules);
  else
    pass("every loaded module was unloaded");

  gpu_release_context(g_context);
  unlink(g_kernel_path);

  if (g_failures > 0) {
    printf(RED "\n%d test(s) failed.\n" CLR, g_failures);
    return 1;
  }
  printf(GREEN "\nAll CUDA arg-table tests passed.\n" CLR);
  return 0;
}
