/*
 * Rainbow Crackalack: cuda_setup.c
 *
 * CUDA Driver API backend for Linux.  Mirrors the function surface
 * of metal_setup.m / opencl_setup.c.  NVRTC is used to compile
 * kernels from .cu source at runtime.
 *
 * All functions return error or print "TODO" and exit until the
 * implementation lands in later tasks.
 */

#include <errno.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>

#include <cuda.h>
#include <nvrtc.h>

#include "gpu_backend.h"

#define CUDA_TODO(_name) do { \
  fprintf(stderr, "cuda_setup: TODO " _name "\n"); \
  exit(-1); \
} while (0)

/* Track which CUcontext to push.  Set once by main thread after
 * gpu_create_context.  All worker threads push this. */
static CUcontext g_default_context = NULL;

/* Per-kernel arg table.  CUfunction is opaque; we key by pointer
 * value into a small linear list.  Each kernel call site can have
 * at most CUDA_MAX_KERNEL_ARGS args.  Keep slots indexed by the
 * arg_index passed to gpu_set_kernel_arg. */
#define CUDA_MAX_KERNEL_ARGS    32
#define CUDA_MAX_TRACKED_KERNELS 64

typedef struct {
  CUfunction kernel;
  /* Storage for arg VALUES (not the host buffer's address).
   * For CUdeviceptr args, value is the CUdeviceptr itself, stored in
   * cuda_arg_storage[slot].  kernelParams holds pointers INTO this
   * storage array. */
  CUdeviceptr storage[CUDA_MAX_KERNEL_ARGS];
  void       *params [CUDA_MAX_KERNEL_ARGS];
  unsigned int max_set_index;  /* highest arg_index set + 1 */
} cuda_kernel_args;

static cuda_kernel_args g_cuda_arg_tables[CUDA_MAX_TRACKED_KERNELS];
static unsigned int     g_cuda_arg_tables_used = 0;

/* Shared 8-byte dummy device allocation used to pad kernel-argument slots that
 * the host never sets.  blurbdust's feature-trimmed host code (no markov / mask
 * paths) binds only the leading args of kernels whose ABI still declares
 * trailing unused* parameters.  cuLaunchKernel reads a pointer for EVERY
 * declared parameter, so a NULL slot yields CUDA_ERROR_INVALID_VALUE
 * ("invalid argument").  Pointing every unset slot at this valid (never
 * dereferenced) allocation makes such launches legal.  (The bandrel fork
 * avoids this by binding all args from its markov/mask code paths.) */
static CUdeviceptr cuda_get_dummy_arg(void) {
  static CUdeviceptr dummy = 0;
  if (dummy == 0) {
    CUresult res = cuMemAlloc(&dummy, 8);
    if (res != CUDA_SUCCESS) {
      const char *err = NULL;
      cuGetErrorString(res, &err);
      fprintf(stderr, "cuda_setup: dummy-arg cuMemAlloc failed: %s\n", err ? err : "(unknown)");
      exit(-1);
    }
  }
  return dummy;
}

static cuda_kernel_args *cuda_get_arg_table(CUfunction k) {
  for (unsigned int i = 0; i < g_cuda_arg_tables_used; i++)
    if (g_cuda_arg_tables[i].kernel == k) return &g_cuda_arg_tables[i];
  if (g_cuda_arg_tables_used >= CUDA_MAX_TRACKED_KERNELS) {
    fprintf(stderr, "cuda_setup: too many tracked kernels (max %d)\n",
            CUDA_MAX_TRACKED_KERNELS);
    exit(-1);
  }
  cuda_kernel_args *t = &g_cuda_arg_tables[g_cuda_arg_tables_used++];
  memset(t, 0, sizeof(*t));
  t->kernel = k;
  /* Pre-populate every slot with the shared dummy pointer so any parameter the
   * host leaves unset is still a valid (non-NULL) CUdeviceptr at launch time.
   * Real args overwrite their slot in gpu_set_kernel_arg(). */
  CUdeviceptr dummy = cuda_get_dummy_arg();
  for (unsigned int i = 0; i < CUDA_MAX_KERNEL_ARGS; i++) {
    t->storage[i] = dummy;
    t->params[i]  = &t->storage[i];
  }
  return t;
}

/* Forward declaration — defined just before gpu_create_context. */
static void cuda_remember_context(CUcontext c);

/* CUDA has no equivalent context error callback.  Provide a no-op
 * definition so CLCREATECONTEXT call sites in consumer code (which
 * are still OpenCL-shaped at this point) don't fail to link. */
void context_callback(const char *errinfo, const void *private_info, size_t cb, void *user_data) {
  (void)errinfo; (void)private_info; (void)cb; (void)user_data;
}

/* CUDA has no platform concept.  We expose a single dummy platform
 * (index 0) so the existing 2-arg consumer API works unchanged. */
void get_platforms_and_devices(int disable_platform,
                               gpu_uint platforms_buffer_size, gpu_platform *platforms, gpu_uint *num_platforms,
                               gpu_uint devices_buffer_size,   gpu_device   *devices,   gpu_uint *num_devices,
                               unsigned int verbose) {
  (void)disable_platform;  /* CUDA: only one "platform"; flag is a no-op */
  (void)verbose;

  CUresult res = cuInit(0);
  if (res != CUDA_SUCCESS) {
    const char *err = NULL;
    cuGetErrorString(res, &err);
    fprintf(stderr, "cuInit failed: %s\n", err ? err : "(unknown)");
    exit(-1);
  }

  int device_count = 0;
  res = cuDeviceGetCount(&device_count);
  if (res != CUDA_SUCCESS || device_count == 0) {
    const char *err = NULL;
    cuGetErrorString(res, &err);
    fprintf(stderr, "cuDeviceGetCount failed or no devices: %s\n", err ? err : "(none)");
    exit(-1);
  }

  if (platforms_buffer_size >= 1 && platforms != NULL)
    platforms[0] = 0;
  if (num_platforms != NULL)
    *num_platforms = 1;

  unsigned int n = (unsigned int)device_count;
  if (n > devices_buffer_size) n = devices_buffer_size;
  for (unsigned int i = 0; i < n; i++) {
    CUdevice dev;
    res = cuDeviceGet(&dev, (int)i);
    if (res != CUDA_SUCCESS) {
      const char *err = NULL;
      cuGetErrorString(res, &err);
      fprintf(stderr, "cuDeviceGet(%u) failed: %s\n", i, err ? err : "(unknown)");
      exit(-1);
    }
    devices[i] = dev;
  }
  if (num_devices != NULL)
    *num_devices = n;
}

void get_device_str(gpu_device device, unsigned int param, char *buf, int buf_len) {
  switch (param) {
    case GPU_DEVICE_NAME:
      cuDeviceGetName(buf, buf_len, device);
      break;
    case GPU_DEVICE_VENDOR:
      /* CUDA doesn't expose a vendor string; force "NVIDIA Corporation". */
      snprintf(buf, buf_len, "NVIDIA Corporation");
      break;
    case GPU_DEVICE_VERSION:
    case GPU_DRIVER_VERSION: {
      int driver = 0;
      cuDriverGetVersion(&driver);
      snprintf(buf, buf_len, "CUDA %d.%d", driver / 1000, (driver % 100) / 10);
      break;
    }
    default:
      buf[0] = '\0';
  }
}

void get_device_bool(gpu_device device, unsigned int param, gpu_bool *b) {
  (void)device;
  if (param == GPU_DEVICE_AVAILABLE) { *b = GPU_TRUE; return; }
  *b = GPU_FALSE;
}

void get_device_uint(gpu_device device, unsigned int param, gpu_uint *u) {
  int v = 0;
  switch (param) {
    case GPU_DEVICE_MAX_COMPUTE_UNITS:
      cuDeviceGetAttribute(&v, CU_DEVICE_ATTRIBUTE_MULTIPROCESSOR_COUNT, device);
      break;
    case GPU_DEVICE_MAX_WORK_GROUP_SIZE:
      cuDeviceGetAttribute(&v, CU_DEVICE_ATTRIBUTE_MAX_THREADS_PER_BLOCK, device);
      break;
    default:
      v = 0;
  }
  *u = (gpu_uint)v;
}

void get_device_ulong(gpu_device device, unsigned int param, gpu_ulong *ul) {
  size_t total = 0;
  switch (param) {
    case GPU_DEVICE_GLOBAL_MEM_SIZE:
      cuDeviceTotalMem(&total, device);
      break;
    default:
      total = 0;
  }
  *ul = (gpu_ulong)total;
}

void print_device_info(gpu_device *devices, gpu_uint num_devices) {
  /* The lookup binary's existing startup banner prints platform/device
   * info by calling get_device_str/uint/ulong directly.  This function
   * is called from a few utility binaries that want a one-shot dump. */
  for (gpu_uint i = 0; i < num_devices; i++) {
    char buf[256] = {0};
    gpu_uint cu = 0, max_wg = 0;
    gpu_ulong mem = 0;
    get_device_str(devices[i], GPU_DEVICE_NAME, buf, sizeof(buf));
    get_device_uint(devices[i], GPU_DEVICE_MAX_COMPUTE_UNITS, &cu);
    get_device_uint(devices[i], GPU_DEVICE_MAX_WORK_GROUP_SIZE, &max_wg);
    get_device_ulong(devices[i], GPU_DEVICE_GLOBAL_MEM_SIZE, &mem);
    printf("Device #%u: %s (SMs=%u, max-threads/block=%u, mem=%llu MB)\n",
           i, buf, cu, max_wg, (unsigned long long)(mem / (1024ULL * 1024ULL)));
  }
}
void gpu_release_device(gpu_device d)                                 { (void)d; /* no-op: CUDA does not require release */ }

/* Read entire file into a malloc'd, NUL-terminated buffer.  Returns NULL
 * (without printing) on error -- callers probe several candidate paths and
 * report failure themselves once all candidates are exhausted. */
static char *cuda_read_file_silent(const char *path) {
  FILE *f = fopen(path, "rb");
  if (!f) return NULL;
  fseek(f, 0, SEEK_END);
  long n = ftell(f);
  fseek(f, 0, SEEK_SET);
  if (n < 0) { fclose(f); return NULL; }
  char *buf = malloc((size_t)n + 1);
  if (!buf) { fclose(f); return NULL; }
  if (fread(buf, 1, (size_t)n, f) != (size_t)n) { free(buf); fclose(f); return NULL; }
  buf[n] = '\0';
  fclose(f);
  return buf;
}

/* Directory containing the running executable (the repo root, where the CUDA/
 * kernel dir and shared.h live).  Lets kernel/include lookups succeed no matter
 * what the current working directory is.  Returns 1 on success, 0 if
 * unavailable (caller then falls back to CWD-relative lookup only). */
static int cuda_exe_dir(char *buf, size_t buf_size) {
  ssize_t n = readlink("/proc/self/exe", buf, buf_size - 1);
  if (n <= 0) return 0;
  buf[n] = '\0';
  char *slash = strrchr(buf, '/');
  if (!slash) return 0;
  *slash = '\0';   /* strip the executable basename, leaving its directory */
  return 1;
}

/* Recursively resolve #include "foo.cu" / "foo.cl" lines by inlining the
 * referenced file's contents.  `dir` is the directory of the file being
 * resolved (where included files are looked up).  Returns a malloc'd
 * NUL-terminated buffer with all includes inlined. */
static char *cuda_resolve_includes(const char *src, const char *dir) {
  /* Quick-and-dirty: scan for lines starting with `#include "`, inline,
   * repeat until no more includes remain.  Adequate for the project's
   * small, well-formed kernel sources. */
  size_t cap = strlen(src) + 1;
  char *out = malloc(cap);
  if (!out) return NULL;
  memcpy(out, src, cap);

  for (;;) {
    char *inc = strstr(out, "#include \"");
    if (!inc) break;
    /* Find newline ending the directive. */
    char *nl = strchr(inc, '\n');
    if (!nl) { fprintf(stderr, "cuda_setup: malformed #include\n"); free(out); return NULL; }
    /* Extract the quoted filename. */
    char *q1 = inc + strlen("#include \"");
    char *q2 = strchr(q1, '\"');
    if (!q2 || q2 > nl) { fprintf(stderr, "cuda_setup: malformed #include\n"); free(out); return NULL; }
    char inc_name[256];
    size_t name_len = (size_t)(q2 - q1);
    if (name_len >= sizeof(inc_name)) { fprintf(stderr, "cuda_setup: #include name too long\n"); free(out); return NULL; }
    memcpy(inc_name, q1, name_len);
    inc_name[name_len] = '\0';

    /* Search, in order: the kernel dir and the project root relative to CWD
     * (fast path when run from the repo root), then both anchored at the
     * executable's directory so generation/lookup also work from any other
     * working dir (e.g. a table-output dir).  shared.h lives in the project
     * root, sibling kernels (rt.cu, string.cu) live in `dir`. */
    char inc_path[1024];
    char exedir[512];
    int have_exe = cuda_exe_dir(exedir, sizeof(exedir));

    snprintf(inc_path, sizeof(inc_path), "%s/%s", dir, inc_name);
    char *inc_src = cuda_read_file_silent(inc_path);
    if (!inc_src)
      inc_src = cuda_read_file_silent(inc_name);
    if (!inc_src && have_exe) {
      char p[1024];
      snprintf(p, sizeof(p), "%s/%s/%s", exedir, dir, inc_name);
      inc_src = cuda_read_file_silent(p);
      if (!inc_src) {
        snprintf(p, sizeof(p), "%s/%s", exedir, inc_name);
        inc_src = cuda_read_file_silent(p);
      }
    }
    if (!inc_src) {
      fprintf(stderr, "cuda_setup: cannot resolve #include \"%s\" (tried %s, %s, and exe dir %s)\n",
              inc_name, inc_path, inc_name, have_exe ? exedir : "(unavailable)");
      free(out);
      return NULL;
    }

    /* Replace the #include line with the inlined source. */
    size_t before_len = (size_t)(inc - out);
    size_t after_len  = strlen(nl + 1);
    size_t inc_len    = strlen(inc_src);
    size_t new_size   = before_len + inc_len + 1 + after_len + 1;
    char *new_out = malloc(new_size);
    if (!new_out) { free(out); free(inc_src); return NULL; }
    memcpy(new_out, out, before_len);
    memcpy(new_out + before_len, inc_src, inc_len);
    new_out[before_len + inc_len] = '\n';
    memcpy(new_out + before_len + inc_len + 1, nl + 1, after_len + 1);

    free(out);
    free(inc_src);
    out = new_out;
  }

  return out;
}

static const char *cuda_dirname(const char *path, char *buf, size_t buf_size) {
  const char *slash = strrchr(path, '/');
  if (!slash) { snprintf(buf, buf_size, "."); return buf; }
  size_t n = (size_t)(slash - path);
  if (n >= buf_size) n = buf_size - 1;
  memcpy(buf, path, n);
  buf[n] = '\0';
  return buf;
}

/* If `in` ends in ".cl", rewrite to "CUDA/<base>.cu" in `out`.
 * Otherwise copy `in` verbatim to `out`.
 * Mirrors metal_setup.m's .cl -> Metal/<base>.metal rewrite. */
static void cuda_rewrite_cl_path(const char *in, char *out, size_t out_size) {
  const char *dot = strrchr(in, '.');
  int written;
  if (dot != NULL && strcmp(dot, ".cl") == 0) {
    size_t base_len = (size_t)(dot - in);
    written = snprintf(out, out_size, "CUDA/%.*s.cu", (int)base_len, in);
  } else {
    written = snprintf(out, out_size, "%s", in);
  }
  if (written < 0 || (size_t)written >= out_size) {
    fprintf(stderr, "cuda_setup: kernel path too long: %s\n", in);
    if (out_size > 0) out[0] = '\0';
  }
}

/* ---- Compiled-PTX disk cache -------------------------------------------
 * NVRTC compilation of the kernels costs ~seconds and is repeated by every
 * process launch.  Batch workflows (--hcmask, or one gen invocation per
 * mask) pay it thousands of times even though the emitted PTX is identical
 * for a given (resolved source, arch, build flags).  Cache the PTX on disk
 * keyed by a content hash so all but the first launch skip NVRTC entirely.
 * Purely an optimization: any failure falls back to compiling.  Disable by
 * setting RCRACK_KERNEL_CACHE=off (or an empty writable dir to relocate it). */

/* FNV-1a 64-bit over a NUL-terminated string, chained via *h. */
static void cuda_fnv1a(uint64_t *h, const char *s) {
  uint64_t x = *h;
  for (; *s; s++) { x ^= (unsigned char)*s; x *= 1099511628211ULL; }
  *h = x;
}

/* mkdir -p (best effort; ignores EEXIST). */
static void cuda_mkdir_p(const char *path) {
  char tmp[512];
  size_t len = strlen(path);
  if (len == 0 || len >= sizeof(tmp)) return;
  memcpy(tmp, path, len + 1);
  if (tmp[len - 1] == '/') tmp[len - 1] = '\0';
  for (char *p = tmp + 1; *p; p++) {
    if (*p == '/') { *p = '\0'; mkdir(tmp, 0777); *p = '/'; }
  }
  mkdir(tmp, 0777);
}

/* Resolve the kernel cache directory into `out`; returns 1 if caching is
 * enabled, 0 if disabled/unavailable. */
static int cuda_cache_dir(char *out, size_t out_size) {
  const char *base = getenv("RCRACK_KERNEL_CACHE");
  if (base && (strcmp(base, "off") == 0 || strcmp(base, "0") == 0)) return 0;
  if (base && base[0]) { snprintf(out, out_size, "%s", base); return 1; }
  const char *xdg = getenv("XDG_CACHE_HOME");
  const char *home = getenv("HOME");
  if (xdg && xdg[0]) { snprintf(out, out_size, "%s/rainbowcrackalack", xdg); return 1; }
  if (home && home[0]) { snprintf(out, out_size, "%s/.cache/rainbowcrackalack", home); return 1; }
  return 0;
}

/* Read an entire cache file, NUL-terminating it.  Returns NULL on any miss. */
static char *cuda_read_cache(const char *path, size_t *out_size) {
  FILE *f = fopen(path, "rb");
  if (!f) return NULL;
  if (fseek(f, 0, SEEK_END) != 0) { fclose(f); return NULL; }
  long n = ftell(f);
  if (n <= 0 || fseek(f, 0, SEEK_SET) != 0) { fclose(f); return NULL; }
  char *buf = malloc((size_t)n + 1);
  if (!buf) { fclose(f); return NULL; }
  size_t rd = fread(buf, 1, (size_t)n, f);
  fclose(f);
  if (rd != (size_t)n) { free(buf); return NULL; }
  buf[n] = '\0';
  *out_size = (size_t)n + 1;   /* include the NUL, matching nvrtcGetPTXSize */
  return buf;
}

/* Write PTX to the cache atomically (temp file + rename).  Best effort. */
static void cuda_write_cache(const char *path, const char *ptx, size_t ptx_size) {
  char tmp[600];
  snprintf(tmp, sizeof(tmp), "%s.tmp.%ld", path, (long)getpid());
  FILE *f = fopen(tmp, "wb");
  if (!f) return;
  size_t n = ptx_size ? ptx_size - 1 : 0;   /* drop trailing NUL; re-added on read */
  if (n && fwrite(ptx, 1, n, f) != n) { fclose(f); unlink(tmp); return; }
  fclose(f);
  if (rename(tmp, path) != 0) unlink(tmp);
}

void load_kernel(gpu_context context, gpu_uint num_devices, const gpu_device *devices,
                 const char *path, const char *kernel_name,
                 gpu_program *program, gpu_kernel *kernel, unsigned int hash_type) {
  (void)context; (void)num_devices;

  /* Mirror metal_setup.m: if caller passed "foo.cl", look up "CUDA/foo.cu". */
  char resolved_path[512];
  cuda_rewrite_cl_path(path, resolved_path, sizeof(resolved_path));

  /* Read kernel source and resolve includes.  Try CWD-relative first (fast
   * path / repo root), then anchored at the executable's directory so the
   * kernel loads regardless of the working directory. */
  char *src = cuda_read_file_silent(resolved_path);
  if (!src) {
    char exedir[512];
    if (cuda_exe_dir(exedir, sizeof(exedir))) {
      char p[1024];
      snprintf(p, sizeof(p), "%s/%s", exedir, resolved_path);
      src = cuda_read_file_silent(p);
    }
  }
  if (!src) {
    fprintf(stderr, "cuda_setup: failed to open kernel '%s' (tried CWD and exe dir): %s\n",
            resolved_path, strerror(errno));
    exit(-1);
  }

  char dir[512];
  cuda_dirname(resolved_path, dir, sizeof(dir));
  char *full = cuda_resolve_includes(src, dir);
  free(src);
  if (!full) exit(-1);

  /* Query compute capability of the first device for arch targeting. */
  int cc_major = 0, cc_minor = 0;
  cuDeviceGetAttribute(&cc_major, CU_DEVICE_ATTRIBUTE_COMPUTE_CAPABILITY_MAJOR, devices[0]);
  cuDeviceGetAttribute(&cc_minor, CU_DEVICE_ATTRIBUTE_COMPUTE_CAPABILITY_MINOR, devices[0]);
  char arch_opt[64];
  snprintf(arch_opt, sizeof(arch_opt), "--gpu-architecture=compute_%d%d", cc_major, cc_minor);

  char hash_type_opt[64];
  snprintf(hash_type_opt, sizeof(hash_type_opt), "-DHASH_TYPE=%u", hash_type);

  /* Cache key: content hash of resolved source + arch + build flags. */
  uint64_t key = 1469598103934665603ULL;   /* FNV-1a offset basis */
  cuda_fnv1a(&key, "rcrack-ptx-v1|");       /* bump to invalidate all entries */
  cuda_fnv1a(&key, full);
  cuda_fnv1a(&key, arch_opt);
  cuda_fnv1a(&key, hash_type_opt);

  char cache_path[640];
  int have_cache = 0;
  { char cdir[512];
    if (cuda_cache_dir(cdir, sizeof(cdir))) {
      cuda_mkdir_p(cdir);
      snprintf(cache_path, sizeof(cache_path), "%s/k_%016llx.ptx", cdir,
               (unsigned long long)key);
      have_cache = 1;
    }
  }

  size_t ptx_size = 0;
  char *ptx = have_cache ? cuda_read_cache(cache_path, &ptx_size) : NULL;

  if (ptx) {
    /* Cache hit: skip NVRTC entirely. */
    fprintf(stderr, "  [cuda] %s: loaded cached PTX (%zu bytes, arch=compute_%d%d)\n",
            kernel_name, ptx_size ? ptx_size - 1 : 0, cc_major, cc_minor);
    free(full);
  } else {
    /* NVRTC compile. */
    nvrtcProgram prog;
    nvrtcResult nres = nvrtcCreateProgram(&prog, full, resolved_path, 0, NULL, NULL);
    if (nres != NVRTC_SUCCESS) {
      fprintf(stderr, "nvrtcCreateProgram failed: %s\n", nvrtcGetErrorString(nres));
      free(full);
      exit(-1);
    }
    const char *options[] = { arch_opt, "--use_fast_math", hash_type_opt };
    struct timespec t0, t1;
    clock_gettime(CLOCK_MONOTONIC, &t0);
    nres = nvrtcCompileProgram(prog, 3, options);
    clock_gettime(CLOCK_MONOTONIC, &t1);
    double compile_secs = (t1.tv_sec - t0.tv_sec) + (t1.tv_nsec - t0.tv_nsec) / 1e9;

    if (nres != NVRTC_SUCCESS) {
      fprintf(stderr, "nvrtcCompileProgram failed: %s\n", nvrtcGetErrorString(nres));
      size_t log_size = 0;
      nvrtcGetProgramLogSize(prog, &log_size);
      if (log_size > 0) {
        char *log = malloc(log_size);
        if (log) {
          nvrtcGetProgramLog(prog, log);
          fprintf(stderr, "NVRTC log:\n%s\n", log);
          free(log);
        }
      }
      nvrtcDestroyProgram(&prog);
      free(full);
      exit(-1);
    }

    /* Retrieve PTX. */
    nvrtcGetPTXSize(prog, &ptx_size);
    ptx = malloc(ptx_size);
    nvrtcGetPTX(prog, ptx);
    fprintf(stderr, "  [cuda] %s: compiled in %.2fs, PTX size %zu bytes (arch=compute_%d%d)\n",
            kernel_name, compile_secs, ptx_size, cc_major, cc_minor);
    nvrtcDestroyProgram(&prog);
    free(full);

    if (have_cache) cuda_write_cache(cache_path, ptx, ptx_size);
  }

  /* Load PTX as a CUmodule and look up the entry function. */
  CUmodule mod;
  CUresult cres = cuModuleLoadData(&mod, ptx);
  free(ptx);
  if (cres != CUDA_SUCCESS) {
    const char *err = NULL;
    cuGetErrorString(cres, &err);
    fprintf(stderr, "cuModuleLoadData failed for %s: %s\n", kernel_name, err ? err : "(unknown)");
    exit(-1);
  }

  CUfunction fn;
  cres = cuModuleGetFunction(&fn, mod, kernel_name);
  if (cres != CUDA_SUCCESS) {
    const char *err = NULL;
    cuGetErrorString(cres, &err);
    fprintf(stderr, "cuModuleGetFunction(%s) failed: %s\n", kernel_name, err ? err : "(unknown)");
    cuModuleUnload(mod);
    exit(-1);
  }

  *program = mod;
  *kernel  = fn;
}

/* Called by gpu_create_context to record the context for worker threads. */
static void cuda_remember_context(CUcontext c) {
  g_default_context = c;
}

gpu_context gpu_create_context(gpu_device device) {
  CUcontext ctx;
  /* Call the stable 3-arg context-create entry point explicitly. CUDA 13+
     headers remap the bare cuCtxCreate to cuCtxCreate_v4 (4-arg), which breaks
     the build on newer toolkits (e.g. gpuhost2's CUDA 13.2); cuCtxCreate_v2 keeps
     the (pctx, flags, dev) signature on every toolkit since CUDA 4.0. */
  CUresult res = cuCtxCreate_v2(&ctx, 0, device);
  if (res != CUDA_SUCCESS) {
    const char *err = NULL;
    cuGetErrorString(res, &err);
    fprintf(stderr, "cuCtxCreate failed: %s\n", err ? err : "(unknown)");
    return NULL;
  }
  cuda_remember_context(ctx);
  return ctx;
}

gpu_queue gpu_create_queue(gpu_context context, gpu_device device) {
  (void)device;
  /* Make sure the requested context is current on this thread. */
  CUresult res = cuCtxSetCurrent(context);
  if (res != CUDA_SUCCESS) {
    const char *err = NULL;
    cuGetErrorString(res, &err);
    fprintf(stderr, "cuCtxSetCurrent failed: %s\n", err ? err : "(unknown)");
    return NULL;
  }
  CUstream stream;
  res = cuStreamCreate(&stream, CU_STREAM_DEFAULT);
  if (res != CUDA_SUCCESS) {
    const char *err = NULL;
    cuGetErrorString(res, &err);
    fprintf(stderr, "cuStreamCreate failed: %s\n", err ? err : "(unknown)");
    return NULL;
  }
  return stream;
}

gpu_buffer gpu_create_buffer(gpu_context context, int flags, size_t size) {
  (void)context;  /* not needed; context is implicit on current thread */
  (void)flags;    /* CUDA doesn't distinguish RO/WO/RW at allocation time */
  CUdeviceptr dptr = 0;

  for (;;) {
    CUresult res = cuMemAlloc(&dptr, size);
    if (res == CUDA_SUCCESS)
      return dptr;

    /* If we ran out of VRAM (likely a co-running GPU process such as hashcat),
     * wait for memory to free up and retry rather than failing the run. */
    if (res == CUDA_ERROR_OUT_OF_MEMORY) {
      gpu_wait_for_free_vram(0, (uint64_t)size);
      continue;
    }

    const char *err = NULL;
    cuGetErrorString(res, &err);
    fprintf(stderr, "cuMemAlloc(%zu) failed: %s\n", size, err ? err : "(unknown)");
    return 0;
  }
}

gpu_buffer gpu_create_and_fill_buffer(gpu_context context, int flags, size_t size, const void *data) {
  gpu_buffer buf = gpu_create_buffer(context, flags, size);
  if (buf == 0) return 0;
  if (data != NULL && size > 0) {
    CUresult res = cuMemcpyHtoD(buf, data, size);
    if (res != CUDA_SUCCESS) {
      const char *err = NULL;
      cuGetErrorString(res, &err);
      fprintf(stderr, "cuMemcpyHtoD failed: %s\n", err ? err : "(unknown)");
      cuMemFree(buf);
      return 0;
    }
  }
  return buf;
}

int gpu_write_buffer(gpu_queue queue, gpu_buffer buf, size_t size, const void *ptr) {
  (void)queue;  /* default stream is synchronous enough; FA path uses one stream per device */
  CUresult res = cuMemcpyHtoD(buf, ptr, size);
  return (res == CUDA_SUCCESS) ? 0 : -1;
}

int gpu_read_buffer(gpu_queue queue, gpu_buffer buf, size_t size, void *ptr) {
  (void)queue;
  CUresult res = cuMemcpyDtoH(ptr, buf, size);
  return (res == CUDA_SUCCESS) ? 0 : -1;
}

void gpu_release_buffer(gpu_buffer buf)  { if (buf != 0) cuMemFree(buf); }
void gpu_release_queue(gpu_queue q)      { if (q) cuStreamDestroy(q); }
void gpu_release_context(gpu_context c)  {
  if (!c) return;
  /* Clear the worker-thread default pointer before destroy so a later
   * gpu_thread_attach can't push a freed context (libcuda's TSD destructor
   * then double-frees on thread exit). */
  if (g_default_context == c) g_default_context = NULL;
  cuCtxDestroy(c);
}
void gpu_release_kernel (gpu_kernel k)   { (void)k; /* CUfunction is owned by its module */ }
void gpu_release_program(gpu_program p)  { if (p) cuModuleUnload(p); }

int gpu_set_kernel_arg(gpu_kernel k, unsigned int idx, size_t size, const void *value) {
  if (idx >= CUDA_MAX_KERNEL_ARGS) {
    fprintf(stderr, "gpu_set_kernel_arg: index %u exceeds max %d\n",
            idx, CUDA_MAX_KERNEL_ARGS);
    return -1;
  }
  cuda_kernel_args *t = cuda_get_arg_table(k);
  /* All our args are pointer-sized (CUdeviceptr).  Store the value
   * (which the caller hands us as &buffer) into storage[idx] and
   * point params[idx] at that storage slot. */
  if (size != sizeof(CUdeviceptr)) {
    fprintf(stderr, "gpu_set_kernel_arg: unsupported arg size %zu (only ptr-sized supported)\n", size);
    return -1;
  }
  t->storage[idx] = *(const CUdeviceptr *)value;
  t->params[idx]  = &t->storage[idx];
  if (idx + 1 > t->max_set_index) t->max_set_index = idx + 1;
  return 0;
}

int gpu_enqueue_kernel(gpu_queue q, gpu_kernel k, unsigned int dim, size_t *gws) {
  (void)dim;  /* always 1 in this codebase */
  cuda_kernel_args *t = cuda_get_arg_table(k);

  /* Block size 256.  Empirical winner across the kernels in this codebase:
   * cuOccupancyMaxPotentialBlockSize-based auto-tuning and a global 128
   * were both tried and produced 4x and 1.4x slower precompute respectively.
   * Per-kernel tuning is left for future work; future kernels with high
   * register pressure may want a different fixed block size. */
  unsigned int block_size = 256;
  unsigned int grid_size = (unsigned int)((gws[0] + block_size - 1) / block_size);
  if (grid_size == 0) grid_size = 1;

  CUresult res = cuLaunchKernel(k,
                                grid_size, 1, 1,
                                block_size, 1, 1,
                                /*sharedMemBytes=*/ 0,
                                q,
                                t->params,
                                NULL);
  if (res != CUDA_SUCCESS) {
    const char *err = NULL;
    cuGetErrorString(res, &err);
    fprintf(stderr, "cuLaunchKernel failed: %s\n", err ? err : "(unknown)");
    return -1;
  }
  return 0;
}

int gpu_flush(gpu_queue q) {
  /* CUDA streams don't have an explicit flush; cuStreamSynchronize
   * is the closest equivalent and matches the OpenCL CLFLUSH semantics
   * used by callers (which then call CLWAIT immediately after). */
  (void)q;
  return 0;
}

int gpu_finish(gpu_queue q) {
  CUresult res = cuStreamSynchronize(q);
  if (res != CUDA_SUCCESS) {
    const char *err = NULL;
    cuGetErrorString(res, &err);
    fprintf(stderr, "cuStreamSynchronize failed: %s (%d)\n", err ? err : "(unknown)", res);
    return -1;
  }
  return 0;
}

/* Reports free/total VRAM in bytes via the current CUDA context.  The device
 * parameter is unused (cuMemGetInfo operates on the current context).  Returns
 * 0 on success, non-zero on failure (caller then skips VRAM waiting). */
int gpu_get_free_memory(gpu_device device, uint64_t *free_bytes, uint64_t *total_bytes) {
  (void)device;
  size_t f = 0, t = 0;
  CUresult res = cuMemGetInfo(&f, &t);
  if (res != CUDA_SUCCESS)
    return -1;
  if (free_bytes)  *free_bytes  = (uint64_t)f;
  if (total_bytes) *total_bytes = (uint64_t)t;
  return 0;
}

int gpu_get_kernel_work_group_info(gpu_kernel k, gpu_device d, unsigned int param, size_t param_size, void *value) {
  (void)d;
  int v = 0;
  CUresult res = CUDA_SUCCESS;
  switch (param) {
    case GPU_KERNEL_WORK_GROUP_SIZE:
      res = cuFuncGetAttribute(&v, CU_FUNC_ATTRIBUTE_MAX_THREADS_PER_BLOCK, k);
      break;
    case GPU_KERNEL_PREFERRED_WORK_GROUP_SIZE_MULTIPLE:
      /* CUDA's warp size = 32 on all current NVIDIA GPUs. */
      v = 32;
      break;
    default:
      v = 0;
  }
  if (res != CUDA_SUCCESS) return -1;
  if (param_size == sizeof(size_t)) {
    *(size_t *)value = (size_t)v;
  } else if (param_size == sizeof(unsigned int)) {
    *(unsigned int *)value = (unsigned int)v;
  } else {
    return -1;
  }
  return 0;
}

/* Per-thread context lifecycle.  Worker threads call attach before any
 * CUDA call and detach after.  No-op on OpenCL/Metal backends. */
void gpu_thread_attach(void) {
  if (g_default_context == NULL) return;  /* called before any context exists */
  CUresult res = cuCtxPushCurrent(g_default_context);
  if (res != CUDA_SUCCESS) {
    const char *err = NULL;
    cuGetErrorString(res, &err);
    fprintf(stderr, "cuCtxPushCurrent failed in worker thread: %s\n", err ? err : "(unknown)");
    exit(-1);
  }
}

void gpu_thread_detach(void) {
  CUcontext old;
  cuCtxPopCurrent(&old);  /* ignore errors; if no context was pushed, this is a no-op */
}

/* --- Backend-neutral VRAM backpressure ----------------------------------
 * In the OpenCL build this lives in gws.c.  The CUDA build defines it here so
 * cuda_setup.o is self-contained: unit_tests links the backend object but not
 * gws.o, and gpu_create_buffer() calls this on CUDA_ERROR_OUT_OF_MEMORY.
 * (blurbdust gws.c does not define it, unlike the bandrel fork.) */
#include <inttypes.h>

#define GPU_VRAM_SAFETY_MARGIN ((uint64_t)256 * 1024 * 1024)
#define GPU_VRAM_POLL_USEC (2 * 1000 * 1000)

void gpu_wait_for_free_vram(gpu_device device, uint64_t needed_bytes) {
  uint64_t required = needed_bytes + GPU_VRAM_SAFETY_MARGIN;
  int waited = 0;

  for (;;) {
    uint64_t free_bytes = 0, total_bytes = 0;

    /* If the backend can't report VRAM, don't wait at all. */
    if (gpu_get_free_memory(device, &free_bytes, &total_bytes) != 0)
      return;

    if (free_bytes >= required) {
      if (waited)
        printf("GPU memory available again (%"PRIu64" MB free); resuming.\n",
               free_bytes / (1024 * 1024));
      return;
    }

    if (!waited) {
      printf("Waiting for GPU memory: need %"PRIu64" MB, %"PRIu64" MB free. "
             "(Is another GPU process running?)\n",
             required / (1024 * 1024), free_bytes / (1024 * 1024));
      fflush(stdout);
      waited = 1;
    }

    usleep(GPU_VRAM_POLL_USEC);
  }
}
