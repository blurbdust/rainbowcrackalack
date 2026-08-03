#ifndef _CUDA_SETUP_H
#define _CUDA_SETUP_H

/*
 * CUDA backend header for blurbdust (Option A, symmetric with opencl_setup.h).
 *
 * blurbdust's thin gpu_backend.h does:  #ifdef USE_CUDA -> #include "cuda_setup.h"
 * and nothing else.  So THIS header owns, for the CUDA build, everything the
 * OpenCL build gets from gpu_backend.h (the neutral gpu_* types + GPU_* flags)
 * PLUS everything it gets from opencl_setup.h (the CL* dispatch macros + the
 * backend function declarations).  The CUDA-side definitions are sourced from
 * bandrel's fat gpu_backend.h USE_CUDA branches and from what cuda_setup.c
 * implements.
 *
 * Only used when compiling with -DUSE_CUDA.  The default OpenCL build never
 * includes this file, so make linux is completely unaffected.
 */

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <cuda.h>

#define MAX_NUM_PLATFORMS 32
#define MAX_NUM_DEVICES 32

/* --- Neutral GPU types (CUDA flavor) --- */
typedef CUdevice      gpu_device;
typedef CUcontext     gpu_context;
typedef CUstream      gpu_queue;
typedef CUmodule      gpu_program;
typedef CUfunction    gpu_kernel;
typedef CUdeviceptr   gpu_buffer;  /* Integer type; CUDA macros use 0, not NULL, as the sentinel. */
typedef uint32_t      gpu_uint;
typedef uint64_t      gpu_ulong;
typedef int           gpu_int;
typedef int           gpu_bool;
typedef int           gpu_platform;  /* CUDA has no platform concept; int placeholder. */

/* --- Neutral memory-flag / status / bool constants --- */
#define GPU_RO  0x1
#define GPU_WO  0x2
#define GPU_RW  0x3

#define GPU_TRUE  1
#define GPU_FALSE 0

#define GPU_SUCCESS 0

/* Legacy CL_ flag aliases so shared macros that still say CL_RO/WO/RW compile. */
#define CL_RO GPU_RO
#define CL_WO GPU_WO
#define CL_RW GPU_RW

/* Kernels are compiled from CUDA/*.cu at runtime via NVRTC. */
#define DEFAULT_BUILD_OPTIONS "-I. -ICUDA"

/* --- Kernel source path helper (host code passes ".cl" literals; cuda_setup.c
 *     rewrites them to CUDA/<base>.cu at load time, so this is provided only for
 *     parity with bandrel's header / any direct callers). --- */
#define GPU_KERNEL_DIR "CUDA/"
#define GPU_KERNEL_EXT ".cu"
#define GPU_KERNEL_PATH(basename) GPU_KERNEL_DIR basename GPU_KERNEL_EXT

/* --- Device / kernel info parameter constants (CUDA has no CL/cl.h) --- */
#define GPU_DEVICE_NAME                 1
#define GPU_DEVICE_VERSION              2
#define GPU_DEVICE_VENDOR               3
#define GPU_DEVICE_AVAILABLE            4
#define GPU_DEVICE_MAX_COMPUTE_UNITS    5
#define GPU_DEVICE_GLOBAL_MEM_SIZE      6
#define GPU_DEVICE_MAX_WORK_GROUP_SIZE  7
#define GPU_DRIVER_VERSION              8

#define GPU_KERNEL_WORK_GROUP_SIZE                    1
#define GPU_KERNEL_PREFERRED_WORK_GROUP_SIZE_MULTIPLE 2

/* CL_ aliases so any consumer still using CL_ names compiles under CUDA. */
#define CL_DEVICE_NAME                GPU_DEVICE_NAME
#define CL_DEVICE_VERSION             GPU_DEVICE_VERSION
#define CL_DEVICE_VENDOR              GPU_DEVICE_VENDOR
#define CL_DEVICE_AVAILABLE           GPU_DEVICE_AVAILABLE
#define CL_DEVICE_MAX_COMPUTE_UNITS   GPU_DEVICE_MAX_COMPUTE_UNITS
#define CL_DEVICE_GLOBAL_MEM_SIZE     GPU_DEVICE_GLOBAL_MEM_SIZE
#define CL_DEVICE_MAX_WORK_GROUP_SIZE GPU_DEVICE_MAX_WORK_GROUP_SIZE
#define CL_DRIVER_VERSION             GPU_DRIVER_VERSION

#define CL_KERNEL_WORK_GROUP_SIZE                    GPU_KERNEL_WORK_GROUP_SIZE
#define CL_KERNEL_PREFERRED_WORK_GROUP_SIZE_MULTIPLE GPU_KERNEL_PREFERRED_WORK_GROUP_SIZE_MULTIPLE

/* --- Backend function declarations (implemented in cuda_setup.c) --- */
void context_callback(const char *errinfo, const void *private_info, size_t cb, void *user_data);

void get_platforms_and_devices(int disable_platform, gpu_uint platforms_buffer_size, gpu_platform *platforms, gpu_uint *num_platforms, gpu_uint devices_buffer_size, gpu_device *devices, gpu_uint *num_devices, unsigned int verbose);

void get_device_bool(gpu_device device, unsigned int param, gpu_bool *b);
void get_device_str(gpu_device device, unsigned int param, char *buf, int buf_len);
void get_device_uint(gpu_device device, unsigned int param, gpu_uint *u);
void get_device_ulong(gpu_device device, unsigned int param, gpu_ulong *ul);

void load_kernel(gpu_context context, gpu_uint num_devices, const gpu_device *devices, const char *path, const char *kernel_name, gpu_program *program, gpu_kernel *kernel, unsigned int hash_type);

void print_device_info(gpu_device *devices, gpu_uint num_devices);

gpu_buffer  gpu_create_and_fill_buffer(gpu_context context, int flags, size_t size, const void *data);
gpu_context gpu_create_context(gpu_device device);
gpu_queue   gpu_create_queue(gpu_context context, gpu_device device);
gpu_buffer  gpu_create_buffer(gpu_context context, int flags, size_t size);
int gpu_write_buffer(gpu_queue queue, gpu_buffer buffer, size_t size, const void *ptr);
int gpu_read_buffer(gpu_queue queue, gpu_buffer buffer, size_t size, void *ptr);
int gpu_set_kernel_arg(gpu_kernel kernel, unsigned int arg_index, size_t arg_size, const void *arg_value);
int gpu_enqueue_kernel(gpu_queue queue, gpu_kernel kernel, unsigned int work_dim, size_t *global_work_size);
int gpu_flush(gpu_queue queue);
int gpu_finish(gpu_queue queue);
int gpu_get_free_memory(gpu_device device, uint64_t *free_bytes, uint64_t *total_bytes);
int gpu_get_kernel_work_group_info(gpu_kernel kernel, gpu_device device, unsigned int param, size_t param_size, void *param_value);
void gpu_release_buffer(gpu_buffer buffer);
void gpu_release_queue(gpu_queue queue);
void gpu_release_context(gpu_context context);
void gpu_release_kernel(gpu_kernel kernel);
void gpu_release_program(gpu_program program);
void gpu_release_device(gpu_device device);

/* Backend-neutral VRAM backpressure helper.  In the OpenCL build this lives in
 * gws.c; the CUDA build provides it inside cuda_setup.c so cuda_setup.o is
 * self-contained (unit_tests links the backend obj but not gws.o). */
void gpu_wait_for_free_vram(gpu_device device, uint64_t needed_bytes);

/* --- Per-thread context lifecycle (CUDA requires attach/detach per worker) --- */
void gpu_thread_attach(void);
void gpu_thread_detach(void);

/* --- Convenience / dispatch macros (same NAMES as opencl_setup.h, CUDA semantics) --- */
#define CLMAKETESTVARS() \
  int err = 0; \
  size_t global_work_size = 1; \
  gpu_queue queue = NULL;

#define _CLCREATEARG(_arg_index, _buffer, _flags, _arg_ptr, _arg_size) \
  { _buffer = gpu_create_and_fill_buffer(context, _flags, _arg_size, _arg_ptr); \
  if (_buffer == 0) { fprintf(stderr, "Error while creating buffer for \"%s\".\n", #_arg_ptr); exit(-1); } \
  if (gpu_set_kernel_arg(kernel, _arg_index, sizeof(gpu_buffer), &_buffer) != 0) { fprintf(stderr, "Error setting kernel argument for %s at index %u.\n", #_arg_ptr, _arg_index); exit(-1); } }

#define CLCREATEARG_ARRAY(_arg_index, _buffer, _flags, _arg, _len) \
  _CLCREATEARG(_arg_index, _buffer, _flags, _arg, _len);

#define CLCREATEARG(_arg_index, _buffer, _flags, _arg, _arg_size) \
  _CLCREATEARG(_arg_index, _buffer, _flags, &_arg, _arg_size);

#define CLCREATEARG_DEBUG(_arg_index, _debug_buffer, _debug_ptr) \
  { _debug_ptr = calloc(DEBUG_LEN, sizeof(unsigned char)); \
    CLCREATEARG_ARRAY(_arg_index, _debug_buffer, GPU_RW, _debug_ptr, DEBUG_LEN); }

#define CLCREATECONTEXT(_context_callback, _device_ptr) \
  gpu_create_context(*(_device_ptr))

#define CLCREATEQUEUE(_context, _device) \
  ((void)err, gpu_create_queue(_context, _device))

#define CLRUNKERNEL(_queue, _kernel, _gws_ptr) \
  { err = gpu_enqueue_kernel(_queue, _kernel, 1, _gws_ptr); if (err != 0) { fprintf(stderr, "gpu_enqueue_kernel failed: %d\n", err); exit(-1); } }

#define CLFLUSH(_queue) \
  { err = gpu_flush(_queue); if (err != 0) { fprintf(stderr, "gpu_flush failed: %d\n", err); exit(-1); } }

#define CLWAIT(_queue) \
  { err = gpu_finish(_queue); if (err != 0) { fprintf(stderr, "gpu_finish failed: %d\n", err); exit(-1); } }

#define CLWRITEBUFFER(_buffer, _len, _ptr) \
  { err = gpu_write_buffer(queue, _buffer, _len, _ptr); \
  if (err != 0) { fprintf(stderr, "gpu_write_buffer failed: %d\n", err); exit(-1); } }

#define CLREADBUFFER(_buffer, _len, _ptr) \
  { err = gpu_read_buffer(queue, _buffer, _len, _ptr); if (err != 0) { fprintf(stderr, "gpu_read_buffer failed: %d\n", err); exit(-1); } }

#define CLFREEBUFFER(_buffer) \
  if (_buffer != 0) { gpu_release_buffer(_buffer); _buffer = 0; }

#define CLRELEASEQUEUE(_queue) \
  if (_queue != NULL) { gpu_release_queue(_queue); _queue = NULL; }

#define CLRELEASECONTEXT(_context) \
  if (_context != NULL) { gpu_release_context(_context); _context = NULL; }

#define CLRELEASEKERNEL(_kernel) \
  if (_kernel != NULL) { gpu_release_kernel(_kernel); _kernel = NULL; }

#define CLRELEASEPROGRAM(_program) \
  if (_program != NULL) { gpu_release_program(_program); _program = NULL; }

#endif /* _CUDA_SETUP_H */
