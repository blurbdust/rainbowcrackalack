/*
 * Rainbow Crackalack: tests/cuda_stub/cuda_stub.c
 *
 * Fake CUDA driver + NVRTC, so cuda_setup.c's host-side bookkeeping can be
 * tested on a machine with no GPU and no CUDA toolkit.  Only the behaviour the
 * tests depend on is modelled:
 *
 *   - cuMemAlloc hands out distinct non-zero CUdeviceptr values and counts
 *     outstanding allocations, so leaks are visible.
 *   - cuModuleGetFunction hands out a fresh CUfunction address per call, which
 *     is what makes cuda_setup.c allocate a new arg table each time.  Flip
 *     cuda_stub_set_recycle_functions() to make it hand back one fixed address
 *     instead, modelling a driver that reuses an unloaded module's function
 *     address -- the case where a stale arg table would silently supply a dead
 *     kernel's argument bindings.
 *   - cuLaunchKernel records the argument values it was handed so a test can
 *     assert what would actually have reached the GPU.
 *
 * Everything else succeeds and does nothing.
 */

#include <pthread.h>
#include <stdlib.h>
#include <string.h>

#include <cuda.h>
#include <nvrtc.h>

#include "cuda_stub.h"

static pthread_mutex_t g_lock = PTHREAD_MUTEX_INITIALIZER;

static unsigned long g_next_handle    = 0x1000;
static int           g_live_allocs    = 0;
static int           g_live_modules   = 0;
static int           g_recycle_funcs  = 0;

/* Last cuLaunchKernel argument values, captured under g_lock. */
static CUdeviceptr   g_last_args[CUDA_STUB_MAX_CAPTURED_ARGS];
static unsigned int  g_last_arg_count = 0;

/* One fixed address used for every function when recycling is enabled. */
static struct CUfunc_st *const g_recycled_func = (struct CUfunc_st *)0x515Ea11;

static void *stub_next_handle_locked(void) {
  return (void *)(g_next_handle += 0x40);
}

/* ---- Test control surface ---------------------------------------------- */

void cuda_stub_set_recycle_functions(int on) {
  pthread_mutex_lock(&g_lock);
  g_recycle_funcs = on;
  pthread_mutex_unlock(&g_lock);
}

int cuda_stub_live_allocations(void) {
  pthread_mutex_lock(&g_lock);
  int n = g_live_allocs;
  pthread_mutex_unlock(&g_lock);
  return n;
}

int cuda_stub_live_modules(void) {
  pthread_mutex_lock(&g_lock);
  int n = g_live_modules;
  pthread_mutex_unlock(&g_lock);
  return n;
}

unsigned int cuda_stub_last_launch_args(CUdeviceptr *out, unsigned int max) {
  pthread_mutex_lock(&g_lock);
  unsigned int n = g_last_arg_count < max ? g_last_arg_count : max;
  memcpy(out, g_last_args, n * sizeof(*out));
  pthread_mutex_unlock(&g_lock);
  return n;
}

void cuda_stub_reset_launch_args(void) {
  pthread_mutex_lock(&g_lock);
  g_last_arg_count = 0;
  memset(g_last_args, 0, sizeof(g_last_args));
  pthread_mutex_unlock(&g_lock);
}

/* ---- Driver API -------------------------------------------------------- */

CUresult cuInit(unsigned int flags) { (void)flags; return CUDA_SUCCESS; }

CUresult cuDriverGetVersion(int *version) { *version = 12040; return CUDA_SUCCESS; }

CUresult cuDeviceGetCount(int *count) { *count = 1; return CUDA_SUCCESS; }

CUresult cuDeviceGet(CUdevice *device, int ordinal) { *device = ordinal; return CUDA_SUCCESS; }

CUresult cuDeviceGetName(char *name, int len, CUdevice dev) {
  (void)dev;
  snprintf(name, (size_t)len, "Stub CUDA Device");
  return CUDA_SUCCESS;
}

CUresult cuDeviceGetAttribute(int *pi, CUdevice_attribute attrib, CUdevice dev) {
  (void)dev;
  switch (attrib) {
    case CU_DEVICE_ATTRIBUTE_COMPUTE_CAPABILITY_MAJOR: *pi = 8;    break;
    case CU_DEVICE_ATTRIBUTE_COMPUTE_CAPABILITY_MINOR: *pi = 9;    break;
    case CU_DEVICE_ATTRIBUTE_MULTIPROCESSOR_COUNT:     *pi = 128;  break;
    case CU_DEVICE_ATTRIBUTE_MAX_THREADS_PER_BLOCK:    *pi = 1024; break;
    default:                                           *pi = 0;    break;
  }
  return CUDA_SUCCESS;
}

CUresult cuDeviceTotalMem(size_t *bytes, CUdevice dev) {
  (void)dev;
  *bytes = (size_t)24 * 1024 * 1024 * 1024;
  return CUDA_SUCCESS;
}

CUresult cuGetErrorString(CUresult error, const char **str) {
  switch (error) {
    case CUDA_SUCCESS:             *str = "no error";              break;
    case CUDA_ERROR_INVALID_VALUE: *str = "invalid argument";      break;
    case CUDA_ERROR_OUT_OF_MEMORY: *str = "out of memory";         break;
    default:                       *str = "stub error";            break;
  }
  return CUDA_SUCCESS;
}

CUresult cuCtxCreate_v2(CUcontext *pctx, unsigned int flags, CUdevice dev) {
  (void)flags; (void)dev;
  pthread_mutex_lock(&g_lock);
  *pctx = (CUcontext)stub_next_handle_locked();
  pthread_mutex_unlock(&g_lock);
  return CUDA_SUCCESS;
}

CUresult cuCtxDestroy(CUcontext ctx)     { (void)ctx; return CUDA_SUCCESS; }
CUresult cuCtxSetCurrent(CUcontext ctx)  { (void)ctx; return CUDA_SUCCESS; }
CUresult cuCtxPushCurrent(CUcontext ctx) { (void)ctx; return CUDA_SUCCESS; }
CUresult cuCtxPopCurrent(CUcontext *pctx) { if (pctx) *pctx = NULL; return CUDA_SUCCESS; }

CUresult cuStreamCreate(CUstream *stream, unsigned int flags) {
  (void)flags;
  pthread_mutex_lock(&g_lock);
  *stream = (CUstream)stub_next_handle_locked();
  pthread_mutex_unlock(&g_lock);
  return CUDA_SUCCESS;
}

CUresult cuStreamSynchronize(CUstream stream) { (void)stream; return CUDA_SUCCESS; }
CUresult cuStreamDestroy(CUstream stream)     { (void)stream; return CUDA_SUCCESS; }

CUresult cuMemAlloc(CUdeviceptr *dptr, size_t size) {
  (void)size;
  pthread_mutex_lock(&g_lock);
  *dptr = (CUdeviceptr)(uintptr_t)stub_next_handle_locked();
  g_live_allocs++;
  pthread_mutex_unlock(&g_lock);
  return CUDA_SUCCESS;
}

CUresult cuMemFree(CUdeviceptr dptr) {
  (void)dptr;
  pthread_mutex_lock(&g_lock);
  g_live_allocs--;
  pthread_mutex_unlock(&g_lock);
  return CUDA_SUCCESS;
}

CUresult cuMemcpyHtoD(CUdeviceptr dst, const void *src, size_t size) {
  (void)dst; (void)src; (void)size; return CUDA_SUCCESS;
}

CUresult cuMemcpyDtoH(void *dst, CUdeviceptr src, size_t size) {
  (void)src;
  if (dst && size) memset(dst, 0, size);
  return CUDA_SUCCESS;
}

CUresult cuMemGetInfo(size_t *free_bytes, size_t *total_bytes) {
  if (free_bytes)  *free_bytes  = (size_t)20 * 1024 * 1024 * 1024;
  if (total_bytes) *total_bytes = (size_t)24 * 1024 * 1024 * 1024;
  return CUDA_SUCCESS;
}

CUresult cuModuleLoadData(CUmodule *module, const void *image) {
  (void)image;
  pthread_mutex_lock(&g_lock);
  *module = (CUmodule)stub_next_handle_locked();
  g_live_modules++;
  pthread_mutex_unlock(&g_lock);
  return CUDA_SUCCESS;
}

CUresult cuModuleGetFunction(CUfunction *func, CUmodule mod, const char *name) {
  (void)mod; (void)name;
  pthread_mutex_lock(&g_lock);
  *func = g_recycle_funcs ? (CUfunction)g_recycled_func
                          : (CUfunction)stub_next_handle_locked();
  pthread_mutex_unlock(&g_lock);
  return CUDA_SUCCESS;
}

CUresult cuModuleUnload(CUmodule mod) {
  (void)mod;
  pthread_mutex_lock(&g_lock);
  g_live_modules--;
  pthread_mutex_unlock(&g_lock);
  return CUDA_SUCCESS;
}

CUresult cuFuncGetAttribute(int *pi, CUfunction_attribute attrib, CUfunction func) {
  (void)attrib; (void)func;
  *pi = 1024;
  return CUDA_SUCCESS;
}

CUresult cuLaunchKernel(CUfunction f,
                        unsigned int gridDimX,  unsigned int gridDimY,  unsigned int gridDimZ,
                        unsigned int blockDimX, unsigned int blockDimY, unsigned int blockDimZ,
                        unsigned int sharedMemBytes, CUstream stream,
                        void **kernelParams, void **extra) {
  (void)f; (void)gridDimX; (void)gridDimY; (void)gridDimZ;
  (void)blockDimX; (void)blockDimY; (void)blockDimZ;
  (void)sharedMemBytes; (void)stream; (void)extra;

  if (kernelParams == NULL)
    return CUDA_ERROR_INVALID_VALUE;

  pthread_mutex_lock(&g_lock);
  g_last_arg_count = 0;
  for (unsigned int i = 0; i < CUDA_STUB_MAX_CAPTURED_ARGS; i++) {
    /* The real driver reads a pointer for every declared parameter; a NULL slot
     * is the CUDA_ERROR_INVALID_VALUE that cuda_setup.c's dummy-arg padding
     * exists to prevent.  Model that so the padding stays under test. */
    if (kernelParams[i] == NULL) {
      pthread_mutex_unlock(&g_lock);
      return CUDA_ERROR_INVALID_VALUE;
    }
    g_last_args[i] = *(CUdeviceptr *)kernelParams[i];
    g_last_arg_count++;
  }
  pthread_mutex_unlock(&g_lock);
  return CUDA_SUCCESS;
}

/* ---- NVRTC ------------------------------------------------------------- */

static const char STUB_PTX[] = "// stub ptx\n.version 8.0\n";

/* A stand-in cubin.  Deliberately binary rather than text: it opens with the
 * ELF magic a real cubin carries, embeds a NUL byte, and ends in a non-NUL
 * byte, so any caller that treats the image as a C string -- or that trims a
 * trailing terminator that is not there -- corrupts it detectably instead of
 * silently round-tripping. */
static const unsigned char STUB_CUBIN[] = {
  0x7f, 'E', 'L', 'F', 0x02, 0x01, 0x01, 0x33,
  0x00, 0x00, 0x00, 0x00, 's', 't', 'u', 'b',
  0x00, 'c', 'u', 'b', 'i', 'n', 0x00, 0xa5
};

const char *nvrtcGetErrorString(nvrtcResult result) {
  return (result == NVRTC_SUCCESS) ? "NVRTC_SUCCESS" : "NVRTC stub error";
}

nvrtcResult nvrtcCreateProgram(nvrtcProgram *prog, const char *src, const char *name,
                               int num_headers, const char **headers, const char **include_names) {
  (void)src; (void)name; (void)num_headers; (void)headers; (void)include_names;
  *prog = (nvrtcProgram)malloc(1);
  return NVRTC_SUCCESS;
}

nvrtcResult nvrtcCompileProgram(nvrtcProgram prog, int num_options, const char **options) {
  (void)prog; (void)num_options; (void)options;
  return NVRTC_SUCCESS;
}

nvrtcResult nvrtcGetProgramLogSize(nvrtcProgram prog, size_t *log_size) {
  (void)prog; *log_size = 1; return NVRTC_SUCCESS;
}

nvrtcResult nvrtcGetProgramLog(nvrtcProgram prog, char *log) {
  (void)prog; log[0] = '\0'; return NVRTC_SUCCESS;
}

nvrtcResult nvrtcGetPTXSize(nvrtcProgram prog, size_t *ptx_size) {
  (void)prog; *ptx_size = sizeof(STUB_PTX); return NVRTC_SUCCESS;
}

nvrtcResult nvrtcGetPTX(nvrtcProgram prog, char *ptx) {
  (void)prog; memcpy(ptx, STUB_PTX, sizeof(STUB_PTX)); return NVRTC_SUCCESS;
}

nvrtcResult nvrtcGetCUBINSize(nvrtcProgram prog, size_t *cubin_size) {
  (void)prog; *cubin_size = sizeof(STUB_CUBIN); return NVRTC_SUCCESS;
}

nvrtcResult nvrtcGetCUBIN(nvrtcProgram prog, char *cubin) {
  (void)prog; memcpy(cubin, STUB_CUBIN, sizeof(STUB_CUBIN)); return NVRTC_SUCCESS;
}

nvrtcResult nvrtcDestroyProgram(nvrtcProgram *prog) {
  if (prog && *prog) { free(*prog); *prog = NULL; }
  return NVRTC_SUCCESS;
}
